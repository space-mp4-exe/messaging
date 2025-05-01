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
    iv = os.urandom(16) # Encrypt message with a random number
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # use CBC to encrypt message
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext

def decrypt_message(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # CBC decryption
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded) + unpadder.finalize()
    return message.decode()

# --- GUI Class ---
class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Messenger")

        self.key = None
        self.conn = None
        self.message_count = 0  # Count messages to trigger key updates

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
        self.output = scrolledtext.ScrolledText(root, width=60, height=60)
        self.output.pack()

    def send_message(self):
        if not self.conn:
            self.output.insert(tk.END, "Not connected to a peer.\n")
            return
        message = self.msg_entry.get()
        iv, ciphertext = encrypt_message(message, self.key)
        self.conn.sendall(iv + ciphertext)
        self.output.insert(tk.END, f"\n Sent Ciphertext: {ciphertext.hex()}\n")
        self.msg_entry.delete(0, tk.END)

        # change key after 5 messages
        self.message_count += 1
        if self.message_count % 5 == 0:
            self.rotate_key()

    # change out keys
    def rotate_key(self):
        new_salt = os.urandom(16)
        self.conn.sendall(b'__ROTATE__' + new_salt)
        password = self.pass_entry.get()
        self.key = derive_key(password, new_salt)
        self.output.insert(tk.END, "\n Encryption key rotated after 5 messages.\n")

    def start_server_thread(self):
        threading.Thread(target=self.server_logic, daemon=True).start()

    def server_logic(self):
        # start a socket to listen to messages
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 12345))
        server.listen(1)
        self.output.insert(tk.END, "[+] Waiting for connection on localhost:12345...\n")
        self.conn, addr = server.accept()

        self.salt = os.urandom(16)
        self.conn.sendall(self.salt)
        password = self.pass_entry.get()
        self.key = derive_key(password, self.salt)

        self.output.insert(tk.END, f"[+] Connected to {addr}\n")
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                if data.startswith(b'__ROTATE__'):
                    self.salt = data[10:26]
                    password = self.pass_entry.get()
                    self.key = derive_key(password, self.salt)
                    self.output.insert(tk.END, "\n Received new key rotation from peer.\n")
                    continue
                iv = data[:16]
                ciphertext = data[16:]
                decrypted = decrypt_message(iv, ciphertext, self.key)
                self.output.insert(tk.END, f"\n Received Ciphertext: {ciphertext.hex()}\n")
                self.output.insert(tk.END, f" Decrypted: {decrypted}\n\n")
            except:
                break

    # connect to server as a client
    def connect_as_client(self):
        try:
            host = self.host_entry.get()
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((host, 12345))
            self.output.insert(tk.END, f"[+] Connected to server at {host}:12345\n")

            self.salt = self.conn.recv(16)
            password = self.pass_entry.get()
            self.key = derive_key(password, self.salt)

            threading.Thread(target=self.listen_to_server, daemon=True).start()

        except Exception as e:
            self.output.insert(tk.END, f"Could not connect: {e}\n")

    # wait to recieve messages from server
    def listen_to_server(self):
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                if data.startswith(b'__ROTATE__'):
                    self.salt = data[10:26]
                    password = self.pass_entry.get()
                    self.key = derive_key(password, self.salt)
                    self.output.insert(tk.END, "\nReceived new key rotation from peer.\n")
                    continue
                iv = data[:16]
                ciphertext = data[16:]
                decrypted = decrypt_message(iv, ciphertext, self.key)
                self.output.insert(tk.END, f"\nReceived Ciphertext: {ciphertext.hex()}\n")
                self.output.insert(tk.END, f"Decrypted: {decrypted}\n\n")
            except:
                break

# --- Main ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessengerApp(root)
    root.mainloop()
