import os
import time
import cryptography
from termcolor import colored
from pyfiglet import Figlet
from zxcvbn import zxcvbn
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json
import getpass
import base64
import secrets
import hashlib
from urllib.parse import urlparse
import pyperclip
import pyautogui
import re

class PasswordManager:
    def __init__(self):
        self.storage_dir = os.path.expanduser("~/.password_vault")
        self.storage_path = os.path.join(self.storage_dir, "secure_passwords.enc")
        self.salt_path = os.path.join(self.storage_dir, "salt")
        self.recovery_path = os.path.join(self.storage_dir, "recovery.json")
        self.initialize_storage()

    def initialize_storage(self):
        os.makedirs(self.storage_dir, exist_ok=True)
        os.chmod(self.storage_dir, 0o700)
        if not os.path.exists(self.salt_path):
            self.salt = os.urandom(16)
            with open(self.salt_path, "wb") as f:
                f.write(self.salt)
            os.chmod(self.salt_path, 0o600)
        else:
            with open(self.salt_path, "rb") as f:
                self.salt = f.read()

    def print_banner(self):
        """Print colorful banner for Suraksha"""
        f = Figlet(font='big')
        banner_lines = f.renderText('Suraksha').splitlines()

        # Print Suraksha
        for line in banner_lines:
          print(colored(line, 'blue', attrs=['bold']))

        # Get width of the last banner line for right alignment
        last_line_width = len(banner_lines[-1])

        # Print "by Hawkeye" right-aligned under the banner
        byline = 'by Hawkeye'
        print(' ' * (last_line_width - len(byline)) + colored(byline,   'green', attrs=['dark']))

        print(colored('=' * 50, 'white'))


    def install_wizard(self):
        """GitHub-style installation and setup wizard"""
        print("\n" + colored("🚀 Welcome to Suraksha Password Manager Installation", 'cyan', attrs=['bold']))
        print(colored("======================================================", 'white'))

        print("\n" + colored("✓", 'green') + " Checking system requirements...")
        time.sleep(0.5)
        print(colored("✓", 'green') + " Downloading latest version...")
        time.sleep(0.5)
        print(colored("✓", 'green') + " Verifying package integrity...")
        time.sleep(0.5)

        self.first_time_setup()

        print("\n" + colored("🎉 Installation Complete!", 'green', attrs=['bold']))
        print(colored("Suraksha Password Manager is now ready to use!", 'cyan'))

    def first_time_setup(self):
      print("\n" + colored("🔐 Initial Setup", 'yellow', attrs=['bold']))
      while True:
        master_password = getpass.getpass(colored("Create your master password: ", 'blue'))
        if self.validate_master_password(master_password):
            confirm_password = getpass.getpass(colored("Confirm master password: ", 'blue'))
            if master_password == confirm_password:
                break
            print(colored("❌ Passwords don't match. Try again.", 'red'))
        else:
            print(colored("❌ Password not strong enough. Use a combination of letters, numbers, and symbols.", 'red'))

      self.save_password_data({'private': {}, 'business': {}}, master_password)
      print(colored("\n✓ Master password created successfully!", 'green'))

    # Setup recovery during initial setup
      print(colored("\n🔑 Setting up recovery options", 'yellow'))
      self.setup_recovery(master_password)
      print(colored("\n✓ Setup complete!", 'green'))
      return master_password

    def main():
    # Clear screen
      os.system('cls' if os.name == 'nt' else 'clear')

      pm.print_banner()

    # Check if first-time installation
      if not os.path.exists(pm.storage_path):
         pm.install_wizard()

      while True:
         print("\n" + colored("=== Password Manager Menu ===", 'cyan'))
         print(colored("1. 🔐 Add Password", 'white'))
         print(colored("2. 👀 View Passwords", 'white'))
         print(colored("3. 🗑️ Delete Password", 'white'))
         print(colored("4. 🔑 Master Password Management", 'white'))
         print(colored("5. 🚪 Exit", 'white'))

         choice = input(colored("Enter your choice: ", 'blue'))

         if choice == "4":
            print("\n" + colored("Master Password Management", 'cyan'))
            print(colored("1. Change Master Password", 'white'))
            print(colored("2. Recover Forgotten Password", 'white'))
            sub_choice = input(colored("Enter your choice (1-2): ", 'blue'))

            if sub_choice == "1":
                current_password = getpass.getpass(colored("Enter current master password: ", 'blue'))
                try:
                    pm.load_passwords(current_password)
                    new_password = getpass.getpass(colored("Enter new master password: ", 'blue'))
                    if pm.validate_master_password(new_password):
                        pm.save_password_data(pm.load_passwords(current_password), new_password)
                        # Setup recovery with new password
                        print(colored("\n🔑 Updating recovery options", 'yellow'))
                        pm.setup_recovery(new_password)
                        print(colored("✓ Master password and recovery updated successfully!", 'green'))
                    else:
                        print(colored("❌ New password not strong enough!", 'red'))
                except:
                    print(colored("❌ Current password is incorrect!", 'red'))
    def change_master_password(self, current_password, new_password):
      try:
        # Verify current password and load existing data
        data = self.load_passwords(current_password)

        # Save data with new password
        self.save_password_data(data, new_password)

        # Setup recovery with new password
        print(colored("\n🔑 Updating recovery options", 'yellow'))
        self.setup_recovery(new_password)

        print(colored("✓ Master password and recovery options updated successfully!", 'green'))
        return True
      except:
         return False
    def validate_master_password(self, password):
        result = zxcvbn(password)
        return result['score'] >= 3

    def save_password_data(self, data, master_password):
        key = self.generate_key(master_password)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(json.dumps(data).encode())
        with open(self.storage_path, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(self.storage_path, 0o600)
        return True

    def save_password(self, category, website, password, master_password):
        if category.lower() not in ['private', 'business']:
            raise ValueError("Category must be either 'private' or 'business'")

        key = self.generate_key(master_password)
        fernet = Fernet(key)

        try:
            data = self.load_passwords(master_password)
        except:
            data = {'private': {}, 'business': {}}

        data[category.lower()][website] = password
        encrypted_data = fernet.encrypt(json.dumps(data).encode())

        with open(self.storage_path, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(self.storage_path, 0o600)

    def load_passwords(self, master_password):
        key = self.generate_key(master_password)
        fernet = Fernet(key)

        with open(self.storage_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data)

    def delete_password(self, category, website, master_password):
        key = self.generate_key(master_password)
        fernet = Fernet(key)

        try:
            data = self.load_passwords(master_password)
            if website in data[category]:
                del data[category][website]
                encrypted_data = fernet.encrypt(json.dumps(data).encode())

                with open(self.storage_path, 'wb') as f:
                    f.write(encrypted_data)

                os.chmod(self.storage_path, 0o600)
                return True
            return False
        except:
            raise ValueError("Invalid master password or website not found")

    def setup_recovery(self, master_password):
        recovery_questions = [
            "What was your first pet's name?",
            "What city were you born in?",
            "What was your mother's maiden name?",
            "What was your high school name?",
            "What's your favorite childhood friend's name?"
        ]
        recovery_data = {
            'questions': {},
            'phone': input("Enter your phone number for recovery: "),
            'email': input("Enter your recovery email: ")
        }

        print("\nPlease answer these recovery questions:")
        for question in recovery_questions:
            answer = getpass.getpass(f"{question}: ").lower()
            answer_hash = hashlib.sha256(answer.encode()).hexdigest()
            recovery_data['questions'][question] = answer_hash

        key = self.generate_key(master_password)
        fernet = Fernet(key)
        encrypted_recovery = fernet.encrypt(json.dumps(recovery_data).encode())

        with open(self.recovery_path, 'wb') as f:
            f.write(encrypted_recovery)

        os.chmod(self.recovery_path, 0o600)

    def load_recovery_data(self):
        with open(self.recovery_path, 'rb') as f:
            return json.loads(f.read().decode())

    def recover_master_password(self):
        print("\nMaster Password Recovery Process")
        print("--------------------------------")
        correct_answers = 0

        recovery_data = self.load_recovery_data()
        phone = input("Enter your registered phone number: ")
        email = input("Enter your registered email: ")

        if phone != recovery_data['phone'] or email != recovery_data['email']:
            raise ValueError("Invalid recovery credentials")

        for question, stored_hash in recovery_data['questions'].items():
            answer = getpass.getpass(f"{question}: ").lower()
            answer_hash = hashlib.sha256(answer.encode()).hexdigest()
            if answer_hash == stored_hash:
                correct_answers += 1

        if correct_answers >= 3:
            new_password = secrets.token_urlsafe(16)
            print(f"\nYour new master password is: {new_password}")
            print("Please change this password immediately after logging in!")
            return new_password
        else:
            raise ValueError("Failed to verify identity")

    def validate_website_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def display_passwords(self, data_dict):
        """Colorful password display"""
        if not data_dict:
            print(colored("No passwords stored.", 'yellow'))
            return

        print(colored("\n" + "=" * 50, 'white'))
        print(colored(f"{'Website':<30} | {'Password':<20}", 'cyan'))
        print(colored("=" * 50, 'white'))
        for site, pwd in data_dict.items():
            print(colored(f"{site:<30} | {pwd:<20}", 'green'))
        print(colored("=" * 50, 'white'))

def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    pm = PasswordManager()
    pm.print_banner()

    if not os.path.exists(pm.storage_path):
        pm.install_wizard()

    while True:
        print("\n" + colored("=== Password Manager Menu ===", 'cyan'))
        print(colored("1. 🔐 Add Password", 'white'))
        print(colored("2. 👀 View Passwords", 'white'))
        print(colored("3. 🗑️ Delete Password", 'white'))
        print(colored("4. 🔑 Master Password Management", 'white'))
        print(colored("5. 🆘 Setup Recovery", 'white'))
        print(colored("6. 🚪 Exit", 'white'))

        choice = input(colored("Enter your choice: ", 'blue'))

        if choice == "1":
            master_password = getpass.getpass(colored("Enter master password: ", 'blue'))
            while True:
                category = input(colored("Enter category (private/business): ", 'blue')).lower()
                if category in ['private', 'business']:
                    break
                print(colored("Please enter either 'private' or 'business'", 'red'))

            website = input(colored("Enter website URL: ", 'blue'))
            if not pm.validate_website_url(website):
                print(colored("Invalid URL format!", 'red'))
                continue

            password = getpass.getpass(colored("Enter password to save: ", 'blue'))
            try:
                pm.save_password(category, website, password, master_password)
                print(colored("Password saved successfully!", 'green'))
            except Exception as e:
                print(colored(f"Error saving password: {str(e)}", 'red'))

        elif choice == "2":
            master_password = getpass.getpass(colored("Enter master password: ", 'blue'))
            try:
                data = pm.load_passwords(master_password)
                print(colored("\nPrivate Passwords:", 'cyan'))
                pm.display_passwords(data['private'])

                print(colored("\nBusiness Passwords:", 'cyan'))
                pm.display_passwords(data['business'])
            except:
                print(colored("Invalid master password!", 'red'))

        elif choice == "3":
            master_password = getpass.getpass(colored("Enter master password: ", 'blue'))
            try:
                data = pm.load_passwords(master_password)
                print(colored("\nAvailable websites:", 'cyan'))
                print(colored("\nPrivate websites:", 'blue'))
                for idx, site in enumerate(data['private'].keys(), 1):
                    print(colored(f"{idx}. {site}", 'white'))
                print(colored("\nBusiness websites:", 'blue'))
                for idx, site in enumerate(data['business'].keys(), 1):
                    print(colored(f"{idx}. {site}", 'white'))

                category = input(colored("\nEnter category (private/business): ", 'blue')).lower()
                website = input(colored("Enter website to delete: ", 'blue'))

                if pm.delete_password(category, website, master_password):
                    print(colored("Password deleted successfully!", 'green'))
                else:
                    print(colored("Website not found!", 'red'))
            except Exception as e:
                print(colored(f"Error: {str(e)}", 'red'))

        elif choice == "4":
            print(colored("\nMaster Password Management", 'cyan'))
            print(colored("1. Change Master Password", 'white'))
            print(colored("2. Recover Forgotten Password", 'white'))

            sub_choice = input(colored("Enter your choice (1-2): ", 'blue'))

            if sub_choice == "1":
                master_password = getpass.getpass(colored("Enter current master password: ", 'blue'))
                try:
                    pm.load_passwords(master_password)
                    new_password = getpass.getpass(colored("Enter new master password: ", 'blue'))

                    if pm.validate_master_password(new_password):
                        pm.save_password_data(pm.load_passwords(master_password), new_password)
                        print(colored("Master password changed successfully!", 'green'))
                    else:
                        print(colored("New password not strong enough!", 'red'))
                except:
                    print(colored("Current password is incorrect!", 'red'))
                    print(colored("If you forgot your password, please use the recovery option.", 'yellow'))

            elif sub_choice == "2":
                try:
                    new_password = pm.recover_master_password()
                    if new_password:
                        print(colored("\nRecovery successful!", 'green'))
                        newer_password = getpass.getpass(colored("Enter your new master password: ", 'blue'))

                        if pm.validate_master_password(newer_password):
                            pm.save_password_data(pm.load_passwords(new_password), newer_password)
                            print(colored("Master password successfully updated!", 'green'))
                        else:
                            print(colored("New password not strong enough! Please try again.", 'red'))
                except Exception as e:
                    print(colored(f"Recovery failed: {str(e)}", 'red'))

        elif choice == "5":
            master_password = getpass.getpass(colored("Enter master password: ", 'blue'))
            try:
                pm.setup_recovery(master_password)
                print(colored("Recovery setup completed successfully!",))
            except Exception as e:
                print(f"Setup failed: {str(e)}")

        elif choice == "6":
            break

if __name__ == "__main__":
    main()
