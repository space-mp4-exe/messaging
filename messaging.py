import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import threading
import os

# --- Crypto functions ---
def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, key: bytes) -> tuple:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext

def decrypt_message(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded) + unpadder.finalize()
    return message.decode()

# --- Networking functions ---
def start_server(app, host='localhost', port=12345):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    app.output.insert(tk.END, f"[+] Waiting for connection on {host}:{port}...\n")
    conn, addr = server.accept()
    app.output.insert(tk.END, f"[+] Connected to {addr}\n")
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            iv = data[:16]
            ciphertext = data[16:]
            decrypted = decrypt_message(iv, ciphertext, app.key)
            app.output.insert(tk.END, f"\n🔐 Received Ciphertext: {ciphertext.hex()}\n")
            app.output.insert(tk.END, f"🔓 Decrypted: {decrypted}\n\n")
        except:
            break

# --- GUI Class ---
class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Messenger")

        self.salt = os.urandom(16)
        self.key = None
        self.conn = None

        # Password input
        self.pass_label = tk.Label(root, text="Shared Password:")
        self.pass_label.pack()
        self.pass_entry = tk.Entry(root, show="*")
        self.pass_entry.pack()

        # Connect as server or client
        self.conn_frame = tk.Frame(root)
        self.conn_frame.pack()
        self.connect_btn = tk.Button(self.conn_frame, text="Start Server", command=self.start_server_thread)
        self.connect_btn.grid(row=0, column=0)
        self.client_btn = tk.Button(self.conn_frame, text="Connect as Client", command=self.connect_as_client)
        self.client_btn.grid(row=0, column=1)
        self.host_entry = tk.Entry(self.conn_frame)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=2)

        # Message input
        self.msg_entry = tk.Entry(root, width=40)
        self.msg_entry.pack()
        self.send_button = tk.Button(root, text="Send Message", command=self.send_message)
        self.send_button.pack()

        # Output
        self.output = scrolledtext.ScrolledText(root, width=60, height=15)
        self.output.pack()

    def derive_key_from_password(self):
        password = self.pass_entry.get()
        if not password:
            self.output.insert(tk.END, "❌ Enter a password.\n")
            return False
        if self.key is None:
            self.key = derive_key(password, self.salt)
        return True

    def send_message(self):
        if not self.derive_key_from_password():
            return
        if not self.conn:
            self.output.insert(tk.END, "❌ Not connected to a peer.\n")
            return
        message = self.msg_entry.get()
        iv, ciphertext = encrypt_message(message, self.key)
        self.conn.sendall(iv + ciphertext)
        self.output.insert(tk.END, f"\n📤 Sent Ciphertext: {ciphertext.hex()}\n")
        self.output.insert(tk.END, f"📝 Plaintext: {message}\n\n")
        self.msg_entry.delete(0, tk.END)

    def start_server_thread(self):
        if not self.derive_key_from_password():
            return
        threading.Thread(target=self.server_logic, daemon=True).start()

    def server_logic(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 12345))  # Accept connections from other devices
        server.listen(1)
        self.output.insert(tk.END, "[+] Waiting for connection on localhost:12345...\n")
        self.conn, addr = server.accept()
        self.output.insert(tk.END, f"[+] Connected to {addr}\n")
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                iv = data[:16]
                ciphertext = data[16:]
                decrypted = decrypt_message(iv, ciphertext, self.key)
                self.output.insert(tk.END, f"\n🔐 Received Ciphertext: {ciphertext.hex()}\n")
                self.output.insert(tk.END, f"🔓 Decrypted: {decrypted}\n\n")
            except:
                break

    def connect_as_client(self):
        if not self.derive_key_from_password():
            return
        try:
            host = self.host_entry.get()
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((host, 12345))
            self.output.insert(tk.END, f"[+] Connected to server at {host}:12345\n")
            threading.Thread(target=self.listen_to_server, daemon=True).start()
        except Exception as e:
            self.output.insert(tk.END, f"❌ Could not connect: {e}\n")

    def listen_to_server(self):
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                iv = data[:16]
                ciphertext = data[16:]
                decrypted = decrypt_message(iv, ciphertext, self.key)
                self.output.insert(tk.END, f"\n🔐 Received Ciphertext: {ciphertext.hex()}\n")
                self.output.insert(tk.END, f"🔓 Decrypted: {decrypted}\n\n")
            except:
                break

# --- Main ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessengerApp(root)
    root.mainloop()
