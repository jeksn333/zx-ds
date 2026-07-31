import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import imaplib
import email
import time
import random
import string
import re
from datetime import datetime

# --- Конфигурация ---
IMAP_SERVER = "imap.smakmail.com"
IMAP_PORT = 993
CHECK_INTERVAL = 5  # секунд между проверками почты

class AccountGenerator:
    def __init__(self, log_callback, stop_event):
        self.log_callback = log_callback
        self.stop_event = stop_event

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_callback(f"[{timestamp}] {message}")

    def generate_username(self, base_name="user"):
        """Генерирует уникальный юзернейм"""
        suffix = ''.join(random.choices(string.digits, k=4))
        return f"{base_name}_{suffix}"

    def generate_password(self, length=12):
        """Генерирует сложный пароль"""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(random.choice(chars) for _ in range(length))

    def check_username_availability(self, username):
        """
        ПРОВЕРКА ЮЗЕРНЕЙМА.
        Здесь должна быть логика запроса к сайту, куда идет регистрация.
        Так как сайт не указан, я делаю имитацию проверки.
        Возвращает True, если логин свободен.
        """
        self.log(f"Проверка доступности логина: {username}...")
        
        # ИМИТАЦИЯ ЗАПРОСА К СЕРВЕРУ (Замените этот блок на реальный requests.get/post)
        # Пример:
        # response = requests.get(f"https://site.com/check_user?name={username}")
        # if "taken" in response.text: return False
        
        time.sleep(0.5) # Имитация задержки сети
        
        # Для демонстрации считаем, что логин свободен в 90% случаев
        if random.random() > 0.1:
            self.log(f"Логин '{username}' свободен.")
            return True
        else:
            self.log(f"Логин '{username}' занят, генерируем новый...")
            return False

    def get_verification_code(self, email_addr, password_mail):
        """Получение кода через IMAP"""
        try:
            self.log(f"Подключение к IMAP {IMAP_SERVER} для {email_addr}...")
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(email_addr, password_mail)
            mail.select("inbox")

            # Поиск непрочитанных писем
            status, messages = mail.search(None, "UNSEEN")
            email_ids = messages[0].split()

            if not email_ids:
                self.log(f"Нет новых писем для {email_addr}. Ждем...")
                mail.logout()
                return None

            # Берем последнее письмо
            latest_email_id = email_ids[-1]
            status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = msg['subject']
                    self.log(f"Письмо найдено! Тема: {subject}")
                    
                    # Извлечение тела письма (упрощенно)
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            cdispo = str(part.get("Content-Disposition"))
                            if ctype == "text/plain" and "attachment" not in cdispo:
                                try:
                                    body = part.get_payload(decode=True).decode()
                                except:
                                    pass
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode()
                        except:
                            pass
                    
                    # Поиск кода (предполагаем, что код из 4-6 цифр)
                    code_match = re.search(r'\b\d{4,6}\b', body)
                    if code_match:
                        code = code_match.group()
                        self.log(f"Код подтверждения получен: {code}")
                        mail.logout()
                        return code
                    else:
                        self.log("Код в письме не найден (неподходящий формат).")
            
            mail.logout()
            return None

        except Exception as e:
            self.log(f"Ошибка IMAP для {email_addr}: {str(e)}")
            return None

    def register_account(self, email_addr, mail_pass):
        """Основной поток регистрации одной почты"""
        try:
            # 1. Генерация данных
            username = self.generate_username()
            
            # 2. Проверка уникальности
            attempts = 0
            while not self.check_username_availability(username) and not self.stop_event.is_set():
                username = self.generate_username()
                attempts += 1
                if attempts > 5:
                    self.log(f"Не удалось подобрать свободный логин для {email_addr}. Пропуск.")
                    return

            if self.stop_event.is_set(): return

            account_password = self.generate_password()
            self.log(f"Данные сгенерированы: Логин={username}, Пароль={account_password}")

            # 3. Отправка формы регистрации (ИМИТАЦИЯ)
            # Здесь должен быть код отправки POST запроса на сайт регистрации
            self.log(f"Отправка регистрационной формы для {username}...")
            time.sleep(1) 
            
            if self.stop_event.is_set(): return

            # 4. Получение кода
            self.log("Ожидание письма с кодом...")
            code = None
            wait_attempts = 0
            max_wait = 3 # Сколько раз проверим почту
            
            while code is None and wait_attempts < max_wait and not self.stop_event.is_set():
                code = self.get_verification_code(email_addr, mail_pass)
                if code is None:
                    wait_attempts += 1
                    if wait_attempts < max_wait:
                        self.log(f"Повторная проверка почты через {CHECK_INTERVAL} сек...")
                        time.sleep(CHECK_INTERVAL)
            
            if code is None:
                self.log(f"Не удалось получить код для {email_addr}. Регистрация прервана.")
                return

            # 5. Подтверждение регистрации (ИМИТАЦИЯ)
            self.log(f"Ввод кода {code} для завершения регистрации {username}...")
            time.sleep(1)
            
            self.log(f"=== УСПЕШНО: Аккаунт {username} зарегистрирован! ===")
            # Здесь можно сохранить результат в файл results.txt
            with open("success_accounts.txt", "a", encoding="utf-8") as f:
                f.write(f"{email_addr}:{mail_pass} | User: {username} | Pass: {account_password} | Code: {code}\n")

        except Exception as e:
            self.log(f"Критическая ошибка в потоке {email_addr}: {e}")

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Auto Register Soft (IMAP)")
        self.root.geometry("800x600")
        
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.generator = None

        self.create_widgets()

    def create_widgets(self):
        # Верхняя панель: Ввод данных
        input_frame = ttk.LabelFrame(self.root, text="Список почт (формат: почта:пароль)", padding=10)
        input_frame.pack(fill="x", padx=10, pady=5)

        self.email_text = scrolledtext.ScrolledText(input_frame, height=8, font=("Consolas", 10))
        self.email_text.pack(fill="x", expand=True)
        self.email_text.insert('1.0', "example@smakmail.com:password123\nuser2@smakmail.com:pass456")

        # Панель управления
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)

        self.btn_start = ttk.Button(control_frame, text="СТАРТ", command=self.start_process)
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(control_frame, text="СТОП", command=self.stop_process, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.status_label = ttk.Label(control_frame, text="Статус: Ожидание", foreground="gray")
        self.status_label.pack(side="right", padx=5)

        # Нижняя панель: Логи
        log_frame = ttk.LabelFrame(self.root, text="Логи процесса", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', bg="#f0f0f0", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)

    def log_message(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert('end', message + "\n")
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def start_process(self):
        raw_data = self.email_text.get("1.0", "end").strip()
        lines = [line.strip() for line in raw_data.split("\n") if line.strip()]
        
        accounts = []
        for line in lines:
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    accounts.append((parts[0], parts[1]))
                else:
                    self.log_message(f"Ошибка формата строки: {line}")
            else:
                self.log_message(f"Пропущена строка (нет пароля): {line}")

        if not accounts:
            messagebox.showwarning("Внимание", "Список почт пуст или неверен!")
            return

        self.stop_event.clear()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_label.config(text="Статус: Работа...", foreground="green")
        
        self.generator = AccountGenerator(self.log_message, self.stop_event)
        
        # Запуск в отдельном потоке, чтобы интерфейс не зависал
        self.worker_thread = threading.Thread(target=self.run_registration, args=(accounts,), daemon=True)
        self.worker_thread.start()

    def run_registration(self, accounts):
        for email_addr, mail_pass in accounts:
            if self.stop_event.is_set():
                break
            self.log_message(f"--- Начало обработки: {email_addr} ---")
            self.generator.register_account(email_addr, mail_pass)
            self.log_message(f"--- Конец обработки: {email_addr} ---\n")
        
        if not self.stop_event.is_set():
            self.log_message("Все задачи завершены.")
            self.root.after(0, self.finish_process)

    def stop_process(self):
        self.log_message("Остановка процесса по запросу пользователя...")
        self.stop_event.set()
        self.finish_process()

    def finish_process(self):
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_label.config(text="Статус: Остановлено", foreground="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
