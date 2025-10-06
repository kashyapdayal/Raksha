import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import hashlib
import base64
import secrets
import string
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet
import pyperclip

# Encryption helpers
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted.encode()).decode()

class SecurePasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RAKSHA")
        self.root.geometry("950x650")

        self.config_path = Path.home() / ".spm_config.json"
        self.master_password_hash_path = Path.home() / ".spm_master.hash"

        self.is_dark_mode = True
        self.master_password = None
        self.encryption_key = None
        self.password_dir = None
        self.security_questions = {
            "What is your biggest fear?": None,
            "What was the first time you cried?": None,
            "What is your favorite childhood memory?": None
        }

        self.load_config()

        self.setup_ui_frames()
        self.apply_theme()

        self.root.bind("<Configure>", self.adjust_button_sizes)

        if not self.master_password_hash_path.exists():
            self.show_registration_screen()
        else:
            self.show_login_screen()

    def setup_ui_frames(self):
        # Top frame for title and mode toggle
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.pack(side=tk.TOP, fill=tk.X)

        self.title_label = ttk.Label(self.top_frame, text="Don't Overthink!", font=("Helvetica", 24, "bold italic"))
        self.title_label.pack(pady=10)

        self.mode_toggle_btn = ttk.Button(self.top_frame, text="Light" if self.is_dark_mode else "Dark",
                                          command=self.toggle_theme)
        self.mode_toggle_btn.pack(padx=10, pady=5, anchor=tk.E)

        # Left navigation frame
        self.nav_frame = ttk.Frame(self.root, width=200)
        self.nav_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.btn_checker = ttk.Button(self.nav_frame, text="Password Checker", command=self.show_checker)
        self.btn_checker.pack(fill=tk.X, padx=5, pady=5)

        self.btn_saver = ttk.Button(self.nav_frame, text="Password Saver", command=self.show_saver)
        self.btn_saver.pack(fill=tk.X, padx=5, pady=5)

        self.btn_viewer = ttk.Button(self.nav_frame, text="Password Viewer", command=self.show_viewer)
        self.btn_viewer.pack(fill=tk.X, padx=5, pady=5)

        self.btn_settings = ttk.Button(self.nav_frame, text="Settings", command=self.show_settings)
        self.btn_settings.pack(fill=tk.X, padx=5, pady=5)

        self.btn_exit = ttk.Button(self.nav_frame, text="BYE!", command=self.root.quit)
        self.btn_exit.pack(fill=tk.X, padx=5, pady=5)

        # Main content frame
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Initially disable nav buttons
        self.set_nav_buttons_state('disabled')

    def adjust_button_sizes(self, event=None):
        width = self.root.winfo_width()
        button_width = max(10, int(width / 50))
        for child in self.nav_frame.winfo_children():
            if isinstance(child, ttk.Button):
                child.config(width=button_width)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()
        self.save_config()

    def apply_theme(self):
        style = ttk.Style()
        if self.is_dark_mode:
            self.root.configure(bg="#121212")
            style.theme_use('clam')
            style.configure('.', background="#121212", foreground="white", fieldbackground="#1E1E1E")
            style.map('TButton', background=[('active', '#006400')])
            self.mode_toggle_btn.config(text="SuN")
            self.title_label.config(foreground="#81C784")  # Light green for dark mode
        else:
            self.root.configure(bg="white")
            style.theme_use('default')
            style.configure('.', background="white", foreground="black", fieldbackground="white")
            style.map('TButton', background=[('active', '#ADD8E6')])
            self.mode_toggle_btn.config(text="MooN")
            self.title_label.config(foreground="#388E3C")  # Dark green for light mode

    def save_config(self):
        if self.master_password is None:
            return  # Prevent saving if master not set

        key = hashlib.sha256(self.master_password.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key[:32])
        fernet = Fernet(fernet_key)

        encrypted_questions = {k: fernet.encrypt(v.encode()).decode() for k, v in self.security_questions.items()}

        config_data = {
            "security_questions": encrypted_questions,
            "password_dir": str(self.password_dir) if self.password_dir else None,
            "dark_mode": self.is_dark_mode
        }
        with open(self.config_path, "w") as f:
            json.dump(config_data, f)

    def load_config(self):
        self.load_theme_preference()

        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                data = json.load(f)
            # Security questions and password dir will be loaded after master password is set
            self.is_dark_mode = data.get("dark_mode", True)
        else:
            self.is_dark_mode = True

    def load_theme_preference(self):
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                config = json.load(f)
                self.is_dark_mode = config.get("dark_mode", True)

    def load_encrypted_config(self):
        if self.config_path.exists() and self.master_password:
            with open(self.config_path, "r") as f:
                data = json.load(f)

            key = hashlib.sha256(self.master_password.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key[:32])
            fernet = Fernet(fernet_key)

            self.security_questions = {}
            for k, v in data.get("security_questions", {}).items():
                try:
                    dec = fernet.decrypt(v.encode()).decode()
                    self.security_questions[k] = dec
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load security questions: {str(e)}")
                    self.security_questions[k] = None

            self.password_dir = Path(data.get("password_dir", str(Path.cwd() / "secure_vault")))
            self.password_dir.mkdir(exist_ok=True)

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def set_nav_buttons_state(self, state):
        for widget in self.nav_frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget != self.btn_exit:  # Exit always enabled
                widget.config(state=state)

    def show_registration_screen(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="First Time Setup", font=("Helvetica", 16, "bold")).pack(pady=10)
        ttk.Label(self.content_frame, text="Set your Master Password", font=("Helvetica", 12)).pack(pady=5)
        print("Do this bruh,The _M_ password")
        self.new_master_entry = ttk.Entry(self.content_frame, show="*", width=30)
        self.new_master_entry.pack(pady=5)
        print("Type Again -_-")
        self.confirm_master_entry = ttk.Entry(self.content_frame, show="*", width=30)
        self.confirm_master_entry.pack(pady=5)

        self.master_status = ttk.Label(self.content_frame, text="", foreground="red")
        self.master_status.pack(pady=5)

        # Questions frame
        self.questions_frame = ttk.Frame(self.content_frame)
        self.questions_frame.pack(pady=10)

        self.question_vars = {}
        for question in self.security_questions:
            ttk.Label(self.questions_frame, text=question, font=("Helvetica", 10)).pack(anchor=tk.W, pady=2)
            var = tk.StringVar()
            entry = ttk.Entry(self.questions_frame, textvariable=var, show="*", width=50)
            entry.pack(pady=2)
            self.question_vars[question] = var

        # Password storage directory
        ttk.Label(self.content_frame, text="Password Storage Directory", font=("Helvetica", 12)).pack(pady=5)
        self.dir_entry = ttk.Entry(self.content_frame, width=50)
        self.dir_entry.pack(pady=5)
        ttk.Button(self.content_frame, text="Browse", command=self.browse_dir).pack(pady=5)

        ttk.Button(self.content_frame, text="Complete Setup", command=self.handle_registration).pack(pady=15)

    def browse_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def handle_registration(self):
        pwd1 = self.new_master_entry.get()
        pwd2 = self.confirm_master_entry.get()

        if pwd1 != pwd2:
            self.master_status.config(text="Passwords do not match.")
            return

        if len(pwd1) < 8:
            self.master_status.config(text="Master password must be at least 8 characters.")
            return

        # Check questions answered
        for q, var in self.question_vars.items():
            answer = var.get().strip()
            if not answer:
                messagebox.showerror("Error", f"Please answer the question: {q}")
                return
            self.security_questions[q] = answer

        directory = self.dir_entry.get().strip()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory for password storage.")
            return

        self.password_dir = Path(directory)
        self.password_dir.mkdir(exist_ok=True)

        self.master_password = pwd1
        self.store_master_password_hash(pwd1)
        self.encryption_key = self.generate_key(pwd1)
        self.save_config()

        messagebox.showinfo("Setup Complete", "Master password and security questions set.")
        self.show_login_screen()

    def store_master_password_hash(self, password):
        hash_val = hashlib.sha512(password.encode()).digest()
        with open(self.master_password_hash_path, "wb") as f:
            f.write(hash_val)

    def verify_master_password(self, password):
        if not self.master_password_hash_path.exists():
            return False
        with open(self.master_password_hash_path, "rb") as f:
            saved_hash = f.read()
        hash_val = hashlib.sha512(password.encode()).digest()
        return secrets.compare_digest(hash_val, saved_hash)

    def generate_key(self, master_password):
        key = hashlib.sha512(master_password.encode()).digest()
        return base64.urlsafe_b64encode(key[:32])

    def show_login_screen(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Fill me First", font=("Helvetica", 14, "bold")).pack(pady=20)

        self.login_entry = ttk.Entry(self.content_frame, show="*", width=30)
        self.login_entry.pack(pady=5)

        self.login_status = ttk.Label(self.content_frame, text="", foreground="red")
        self.login_status.pack(pady=5)

        ttk.Button(self.content_frame, text="Login", command=self.handle_login).pack(pady=20)

        self.login_attempts_left = 3

    def handle_login(self):
        pwd = self.login_entry.get()
        if self.verify_master_password(pwd):
            self.master_password = pwd
            self.encryption_key = self.generate_key(pwd)
            self.load_encrypted_config()
            self.set_nav_buttons_state('normal')
            self.show_checker()
        else:
            self.login_attempts_left -= 1
            self.login_status.config(text=f"_Nop bruh think again_. Attempts left: {self.login_attempts_left}")
            if self.login_attempts_left == 0:
                self.root.destroy()

    def show_checker(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Password Strength Checker", font=("Helvetica", 14, "bold")).pack(pady=15)

        self.check_entry = ttk.Entry(self.content_frame, width=40, show="*")
        self.check_entry.pack(pady=5)

        ttk.Button(self.content_frame, text="Check Strength", command=self.check_password).pack(pady=10)

        self.strength_label = ttk.Label(self.content_frame, text="", font=("Helvetica", 12))
        self.strength_label.pack(pady=5)

        self.suggestions_text = tk.Text(self.content_frame, height=6, width=50, state=tk.DISABLED)
        self.suggestions_text.pack(pady=5)

    def check_password(self):
        pwd = self.check_entry.get()
        score = self.password_strength_score(pwd)
        self.strength_label.config(text=f"Strength score: {score}/10")

        self.suggestions_text.config(state=tk.NORMAL)
        self.suggestions_text.delete("1.0", tk.END)
        if score < 7:
            suggestions = self.generate_strong_passwords()
            self.suggestions_text.insert(tk.END, "Suggestions for strong passwords:\n" + "\n".join(suggestions))
        self.suggestions_text.config(state=tk.DISABLED)

    def password_strength_score(self, password):
        score = 0
        length = len(password)
        if length >= 16:
            score += 5
        elif length >= 12:
            score += 3
        elif length >= 8:
            score += 2

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        if has_lower:
            score += 1
        if has_upper:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 2

        if password.lower() in ["password", "123456", "qwerty"]:
            score -= 3

        return max(1, min(score, 10))

    def generate_strong_passwords(self, count=3, length=18):
        suggestions = []
        chars = string.ascii_letters + string.digits + string.punctuation
        for _ in range(count):
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if self.password_strength_score(pwd) >= 8:
                suggestions.append(pwd)
        return suggestions

    def show_saver(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Password Saver", font=("Helvetica", 14, "bold")).pack(pady=15)

        ttk.Label(self.content_frame, text="Name:").pack(anchor=tk.W, pady=(10, 0))
        self.name_entry = ttk.Entry(self.content_frame, width=40)
        self.name_entry.pack(pady=5)

        ttk.Label(self.content_frame, text="Password:").pack(anchor=tk.W, pady=(10, 0))
        self.pass_entry = ttk.Entry(self.content_frame, show="*", width=40)
        self.pass_entry.pack(pady=5)

        ttk.Button(self.content_frame, text="Generate Strong Password", command=self.generate_and_insert).pack(pady=5)
        ttk.Button(self.content_frame, text="Save Password", command=self.save_password).pack(pady=10)

        self.save_status = ttk.Label(self.content_frame, text="", font=("Helvetica", 11))
        self.save_status.pack(pady=5)

    def generate_and_insert(self):
        strong_pwd = self.generate_strong_passwords(1)[0]
        self.pass_entry.delete(0, tk.END)
        self.pass_entry.insert(0, strong_pwd)

    def save_password(self):
        name = self.name_entry.get()
        pwd = self.pass_entry.get()
        if not name or not pwd:
            self.save_status.config(text="Name and password cannot be empty.", foreground="red")
            return
        if self.password_dir is None:
            self.save_status.config(text="Password directory not set.", foreground="red")
            return

        filename = hashlib.sha512(name.encode()).hexdigest()[:20] + ".svt"
        filepath = self.password_dir / filename

        data = json.dumps({"name": name, "password": pwd})
        encrypted = encrypt_data(data, self.encryption_key)

        with open(filepath, "w") as f:
            f.write(encrypted)

        self.save_status.config(text=f"Password saved securely at {filepath}", foreground="green")
    def show_viewer(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Password Viewer", font=("Helvetica", 14, "bold")).pack(pady=15)

        self.viewer_listbox = tk.Listbox(self.content_frame, height=15, width=60)
        self.viewer_listbox.pack(pady=10)
        self.viewer_listbox.bind("<Double-Button-1>", self.view_selected_password)

        self.refresh_password_list()

    def refresh_password_list(self):
        self.viewer_listbox.delete(0, tk.END)
        if self.password_dir is None:
            self.viewer_listbox.insert(tk.END, "Password directory not set.")
            return
        # Only list files with .svt extension from the configured directory
        svt_files = list(self.password_dir.glob("*.svt"))
        if not svt_files:
            self.viewer_listbox.insert(tk.END, "No saved passwords found in the directory.")
        for file in svt_files:
            self.viewer_listbox.insert(tk.END, file.name)  # Shows hashed filename; decrypt to see real name

    def view_selected_password(self, event):
        selection = self.viewer_listbox.curselection()
        if not selection:
            return
        filename = self.viewer_listbox.get(selection[0])
        filepath = self.password_dir / filename

        # Step 1: Check if it's a valid .svt file (quick filter for tool-created files)
        if not filename.endswith('.svt'):
            messagebox.showwarning("Invalid File", "This file is not a valid encrypted password file (.svt) for this tool.")
            return

        try:
            # Step 2: Read and attempt decryption
            with open(filepath, "r") as f:
                encrypted = f.read()
            decrypted = decrypt_data(encrypted, self.encryption_key)

            # Step 3: Validate it's properly encoded by this tool (expected JSON structure)
            data = json.loads(decrypted)
            if not all(k in data for k in ('name', 'password')):
                raise ValueError("Decrypted data does not have the expected structure (missing 'name' or 'password').")

            # Display with the original saved name
            details = f"Name: {data['name']}\nPassword: {data['password']}"
            messagebox.showinfo("Password Details", details)
            pyperclip.copy(data['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        except Exception as e:
            # Handle failures (e.g., not encrypted by this tool, wrong key, or corrupted)
            messagebox.showerror("Error", f"Could not decrypt or invalid file (may not be encoded by this tool): {str(e)}")

    def show_settings(self):
        self.clear_content()
        ttk.Label(self.content_frame, text="Settings", font=("Helvetica", 14, "bold")).pack(pady=15)

        ttk.Button(self.content_frame, text="Change Master Password", command=self.change_master_password).pack(pady=10)

        ttk.Label(self.content_frame, text="Edit Password Saving Directory", font=("Helvetica", 12)).pack(pady=10)
        self.dir_entry = ttk.Entry(self.content_frame, width=50)
        self.dir_entry.insert(0, str(self.password_dir) if self.password_dir else "")
        self.dir_entry.pack(pady=5)

        ttk.Button(self.content_frame, text="Browse", command=self.browse_dir_settings).pack(pady=5)
        ttk.Button(self.content_frame, text="Save Directory", command=self.save_password_directory).pack(pady=10)

        self.setting_status = ttk.Label(self.content_frame, text="", font=("Helvetica", 11))
        self.setting_status.pack(pady=5)

    def browse_dir_settings(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def change_master_password(self):
        # Verify security questions
        for question, correct_answer in self.security_questions.items():
            answer = simpledialog.askstring("Security Question", question, show="*")
            if answer != correct_answer:
                messagebox.showerror("Error", "Incorrect answer to security question.")
                return

        new_pwd = simpledialog.askstring("New Master Password", "Enter new master password", show="*")
        confirm_pwd = simpledialog.askstring("Confirm", "Confirm new master password", show="*")

        if new_pwd != confirm_pwd or len(new_pwd) < 8:
            messagebox.showerror("Error", "Passwords do not match or too short.")
            return

        self.store_master_password_hash(new_pwd)
        self.master_password = new_pwd
        self.encryption_key = self.generate_key(new_pwd)
        self.save_config()

        messagebox.showinfo("Success", "Master password changed. Note: Existing passwords may need re-saving.")

    def save_password_directory(self):
        new_dir = self.dir_entry.get()
        if not os.path.isdir(new_dir):
            messagebox.showerror("Error", "Invalid directory.")
            return
        self.password_dir = Path(new_dir)
        self.password_dir.mkdir(exist_ok=True)
        self.save_config()
        messagebox.showinfo("Success", "Directory updated.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurePasswordManagerApp(root)
    root.mainloop()
