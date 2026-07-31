import base64
import datetime
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
import webbrowser

from flask import Flask, Response, jsonify, render_template, request as flask_request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.join(BASE_DIR, 'ca')
CA_KEY = os.path.join(CA_DIR, 'ca.key')
CA_CERT = os.path.join(CA_DIR, 'ca.crt')
CERT_DIR = os.path.join(CA_DIR, 'certs')

BUFSIZE = 65536
MAX_CAPTURE = 512 * 1024
MAX_STORED = 3000

state = {
    'running': False,
    'requests': [],
    'seq': 0,
    'lock': threading.Lock(),
    'srv_socket': None,
    'proxy_thread': None,
    'config': {'host': '127.0.0.1', 'port': 8080, 'user': '', 'pass': ''},
}

cert_cache = {}
cert_lock = threading.Lock()

sse_clients = set()
sse_lock = threading.Lock()


def sse_emit(event, data):
    msg = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    with sse_lock:
        clients = list(sse_clients)
    for q in clients:
        try:
            q.put_nowait(msg)
        except queue.Full:
            pass


def ensure_ca():
    os.makedirs(CA_DIR, exist_ok=True)
    if os.path.exists(CA_KEY) and os.path.exists(CA_CERT):
        with open(CA_KEY, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Request Interceptor Local CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Request Interceptor'),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    with open(CA_KEY, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(CA_CERT, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def get_host_cert(host):
    with cert_lock:
        if host in cert_cache:
            return cert_cache[host]
        ca_key, _ = ensure_ca()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.utcnow()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(ca_key, hashes.SHA256()))
        os.makedirs(CERT_DIR, exist_ok=True)
        fname = re.sub(r'[^A-Za-z0-9._-]', '_', host)
        kf = os.path.join(CERT_DIR, fname + '.key')
        cf = os.path.join(CERT_DIR, fname + '.crt')
        with open(kf, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        with open(cf, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        pair = (kf, cf)
        cert_cache[host] = pair
        return pair


def recv_until(sock, marker):
    data = b''
    while marker not in data:
        chunk = sock.recv(BUFSIZE)
        if not chunk:
            break
        data += chunk
        if len(data) > (1 << 20):
            break
    return data


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def recv_line(sock):
    buf = b''
    while not buf.endswith(b'\r\n'):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > (1 << 16):
            break
    return buf


def parse_headers(raw):
    headers = {}
    for line in raw.split(b'\r\n'):
        if b':' not in line:
            continue
        k, v = line.split(b':', 1)
        headers[k.decode('latin-1').strip().lower()] = v.decode('latin-1').strip()
    return headers


def split_host_port(hp, default):
    hp = hp.strip()
    if hp.startswith('['):
        m = re.match(r'\[([^\]]+)\](?::(\d+))?', hp)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else default
            return host, port
    if ':' in hp:
        host, _, p = hp.rpartition(':')
        try:
            port = int(p)
        except ValueError:
            port = default
        return host, port
    return hp, default


def decode_body(data, content_type=''):
    if not data:
        return '', 'text'
    ct = (content_type or '').lower()
    if 'json' in ct or data[:1] in (b'{', b'['):
        try:
            return json.dumps(json.loads(data.decode('utf-8')), ensure_ascii=False, indent=2), 'json'
        except Exception:
            pass
    if any(k in ct for k in ('image', 'pdf', 'zip', 'octet', 'audio', 'video', 'font', 'wasm')):
        return '[binary: %d bytes]' % len(data), 'binary'
    for enc in ('utf-8', 'latin-1'):
        try:
            return data.decode(enc), 'text'
        except UnicodeDecodeError:
            continue
    return '[binary: %d bytes]' % len(data), 'binary'


def format_headers(headers):
    lines = []
    for k, v in headers.items():
        lines.append('%s: %s' % (k, v))
    return '\n'.join(lines)


def add_request(entry):
    with state['lock']:
        state['seq'] += 1
        entry['id'] = state['seq']
        state['requests'].append(entry)
        if len(state['requests']) > MAX_STORED:
            del state['requests'][0]
    sse_emit('request', entry)


def read_chunked_forward(up, stream):
    decoded = b''
    while True:
        line = recv_line(up)
        if not line:
            break
        try:
            size = int(line.split(b';')[0].strip(), 16)
        except ValueError:
            size = 0
        if size == 0:
            while True:
                t = recv_line(up)
                if not t or t in (b'\r\n', b''):
                    break
            break
        data = recv_exact(up, size)
        crlf = recv_exact(up, 2)
        stream.sendall(line + data + crlf)
        if len(decoded) < MAX_CAPTURE:
            decoded += data
            if len(decoded) > MAX_CAPTURE:
                decoded = decoded[:MAX_CAPTURE]
    stream.sendall(b'0\r\n\r\n')
    return decoded


def handle_stream(stream, target_host, target_port, scheme, base_url, initial_head=b''):
    while True:
        entry = None
        up = None
        try:
            head = initial_head or recv_until(stream, b'\r\n\r\n')
            initial_head = b''
            if not head:
                return
            head_end = head.index(b'\r\n\r\n') + 4
            first_line, _, rest = head.partition(b'\r\n')
            parts = first_line.decode('latin-1', 'replace').split(' ')
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else 'HTTP/1.1'
            headers = parse_headers(rest[:rest.index(b'\r\n\r\n')])
            started = time.time()

            body = head[head_end:]
            clen = 0
            try:
                clen = int(headers.get('content-length', 0) or 0)
            except ValueError:
                clen = 0
            while len(body) < clen:
                chunk = stream.recv(min(BUFSIZE, clen - len(body)))
                if not chunk:
                    break
                if len(body) < MAX_CAPTURE:
                    body += chunk[:MAX_CAPTURE - len(body)]
                else:
                    body += chunk
            body = body[:MAX_CAPTURE]

            url = base_url + target
            up = socket.create_connection((target_host, target_port), timeout=30)
            up.settimeout(30)
            if scheme == 'https':
                uctx = ssl.create_default_context()
                uctx.check_hostname = False
                uctx.verify_mode = ssl.CERT_NONE
                try:
                    up = uctx.wrap_socket(up, server_hostname=target_host)
                except ssl.SSLError as e:
                    entry = {'error': 'TLS to upstream failed: %s' % e}
                    entry['method'] = method
                    entry['url'] = url
                    entry['scheme'] = scheme
                    entry['host'] = target_host
                    entry['port'] = target_port
                    entry['path'] = target
                    entry['version'] = version
                    entry['req_headers'] = headers
                    entry['req_body'] = decode_body(body, headers.get('content-type', ''))[0]
                    entry['status'] = 0
                    entry['duration_ms'] = 0
                    up.close()
                    up = None
                    add_request(entry)
                    return
            up.sendall(head + body[len(head[head_end:]):])

            rhead = recv_until(up, b'\r\n\r\n')
            if not rhead:
                raise ConnectionError('no response from upstream')
            rhead_end = rhead.index(b'\r\n\r\n') + 4
            status_line = rhead.split(b'\r\n', 1)[0]
            rheaders = parse_headers(rhead[:rhead_end])
            status_code = 0
            try:
                status_code = int(status_line.decode('latin-1').split(' ')[1])
            except (ValueError, IndexError):
                pass
            te = rheaders.get('transfer-encoding', '').lower()
            rclen = 0
            try:
                rclen = int(rheaders.get('content-length', 0) or 0)
            except ValueError:
                rclen = 0
            rbody = b''

            if te == 'chunked':
                stream.sendall(rhead)
                rbody = read_chunked_forward(up, stream)
            elif rclen or method == 'HEAD' or status_code in (204, 304):
                rbody = rhead[rhead_end:]
                head_sent = False
                while len(rbody) < rclen:
                    chunk = up.recv(min(BUFSIZE, rclen - len(rbody)))
                    if not chunk:
                        break
                    if not head_sent:
                        stream.sendall(rhead)
                        head_sent = True
                    if len(rbody) < MAX_CAPTURE:
                        add = min(len(chunk), MAX_CAPTURE - len(rbody))
                        rbody += chunk[:add]
                        chunk = chunk[add:]
                    if chunk:
                        stream.sendall(chunk)
                if not head_sent:
                    stream.sendall(rhead)
            else:
                up.settimeout(8)
                stream.sendall(rhead)
                try:
                    while True:
                        chunk = up.recv(BUFSIZE)
                        if not chunk:
                            break
                        stream.sendall(chunk)
                        if len(rbody) < MAX_CAPTURE:
                            rbody += chunk
                            if len(rbody) > MAX_CAPTURE:
                                rbody = rbody[:MAX_CAPTURE]
                except socket.timeout:
                    pass

            dur = int((time.time() - started) * 1000)
            req_body, _ = decode_body(body, headers.get('content-type', ''))
            resp_body, _ = decode_body(rbody, rheaders.get('content-type', ''))
            entry = {
                'method': method,
                'url': url,
                'scheme': scheme,
                'host': target_host,
                'port': target_port,
                'path': target,
                'version': version,
                'status': status_code,
                'duration_ms': dur,
                'req_headers': headers,
                'req_body': req_body,
                'req_size': len(body),
                'resp_headers': rheaders,
                'resp_body': resp_body,
                'resp_size': len(rbody),
                'time': datetime.datetime.now().strftime('%H:%M:%S'),
            }
            add_request(entry)
            if (headers.get('connection', '').lower() == 'close'
                    or version == 'HTTP/1.0'
                    or rheaders.get('connection', '').lower() == 'close'):
                return
        except (ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
            if entry is None:
                print('[proxy] request failed:', e)
            return
        finally:
            if up is not None:
                try:
                    up.close()
                except OSError:
                    pass


def handle_client(conn, addr):
    try:
        conn.settimeout(60)
        head = recv_until(conn, b'\r\n\r\n')
        if not head:
            return
        first_line, _, rest = head.partition(b'\r\n')
        parts = first_line.decode('latin-1', 'replace').split(' ')
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]
        headers = parse_headers(rest[:rest.index(b'\r\n\r\n')])

        cfg = state['config']
        if cfg.get('user'):
            want = 'Basic ' + base64.b64encode(('%s:%s' % (cfg['user'], cfg['pass'])).encode()).decode()
            if headers.get('proxy-authorization', '') != want:
                conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                             b'Proxy-Authenticate: Basic realm="interceptor"\r\n'
                             b'Content-Length: 0\r\n\r\n')
                return

        if method == 'CONNECT':
            target_host, target_port = split_host_port(target, 443)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            kf, cf = get_host_cert(target_host)
            ctx.load_cert_chain(cf, kf)
            try:
                stream = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                return
            handle_stream(stream, target_host, target_port, 'https',
                          'https://%s' % (target_host if target_port == 443 else '%s:%d' % (target_host, target_port)))
        elif target.startswith('https://'):
            target_host, target_port = split_host_port(target[8:].split('/', 1)[0], 443)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            kf, cf = get_host_cert(target_host)
            ctx.load_cert_chain(cf, kf)
            try:
                stream = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                return
            handle_stream(stream, target_host, target_port, 'https',
                          'https://%s' % (target_host if target_port == 443 else '%s:%d' % (target_host, target_port)))
        else:
            if target.startswith('http://'):
                url_host = target[7:].split('/', 1)[0]
                th, tp = split_host_port(url_host, 80)
                base = ''
            else:
                hdr_host = headers.get('host', '')
                th, tp = split_host_port(hdr_host, 80)
                base = 'http://%s' % hdr_host
            handle_stream(conn, th, tp, 'http', base, initial_head=head)
    except (ConnectionError, socket.timeout, ssl.SSLError, OSError) as e:
        print('[proxy] client error:', e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def proxy_server():
    cfg = state['config']
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((cfg['host'], cfg['port']))
    srv.listen(200)
    srv.settimeout(1)
    state['srv_socket'] = srv
    print('[proxy] listening on %s:%s' % (cfg['host'], cfg['port']))
    while state['running']:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    try:
        srv.close()
    except OSError:
        pass
    state['srv_socket'] = None
    print('[proxy] stopped')


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    with state['lock']:
        total = len(state['requests'])
    return jsonify({'running': state['running'], 'config': state['config'], 'total': total, 'ca': CA_CERT})


@app.route('/api/requests')
def api_requests():
    limit = flask_request.args.get('limit', default=300, type=int)
    since = flask_request.args.get('since', default=0, type=int)
    with state['lock']:
        items = [r for r in state['requests'] if r['id'] > since]
        if limit and len(items) > limit:
            items = items[-limit:]
        out = list(items)
    return jsonify(out)


@app.route('/api/requests/<int:rid>')
def api_request(rid):
    with state['lock']:
        for r in state['requests']:
            if r['id'] == rid:
                return jsonify(r)
    return jsonify({'error': 'not found'}), 404


@app.route('/api/start', methods=['POST'])
def api_start():
    if state['running']:
        return jsonify({'error': 'proxy already running'}), 400
    data = flask_request.get_json(force=True, silent=True) or {}
    cfg = state['config']
    for k in ('host', 'port', 'user', 'pass'):
        if k in data and data[k] is not None:
            cfg[k] = data[k]
    try:
        cfg['port'] = int(cfg['port'])
    except (TypeError, ValueError):
        cfg['port'] = 8080
    state['running'] = True
    t = threading.Thread(target=proxy_server, daemon=True)
    state['proxy_thread'] = t
    t.start()
    time.sleep(0.35)
    if not t.is_alive():
        state['running'] = False
        return jsonify({'error': 'cannot bind %s:%s (port busy?)' % (cfg['host'], cfg['port'])}), 500
    return jsonify({'ok': True, 'config': cfg})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    if not state['running']:
        return jsonify({'ok': True})
    state['running'] = False
    srv = state['srv_socket']
    if srv:
        try:
            srv.close()
        except OSError:
            pass
    return jsonify({'ok': True})


@app.route('/api/clear', methods=['POST'])
def api_clear():
    with state['lock']:
        state['requests'].clear()
    sse_emit('cleared', {})
    return jsonify({'ok': True})


@app.route('/api/open-ca', methods=['POST'])
def api_open_ca():
    try:
        os.startfile(CA_DIR)
    except OSError as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'ok': True})


@app.route('/api/events')
def sse_endpoint():
    q = queue.Queue(maxsize=1000)
    with sse_lock:
        sse_clients.add(q)

    def gen():
        try:
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield msg
                except queue.Empty:
                    yield ': keepalive\n\n'
        finally:
            with sse_lock:
                sse_clients.discard(q)

    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    ensure_ca()
    port = int(os.environ.get('INTERCEPTOR_PORT', '5000'))
    if os.environ.get('INTERCEPTOR_NO_BROWSER') != '1':
        webbrowser.open('http://127.0.0.1:%d/' % port)
    app.run(host='127.0.0.1', port=port, threaded=True, debug=False)
