# MAIN.py

import os
import sqlite3
import base64
from collections import namedtuple
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import simpledialog, messagebox, ttk
import tkinter as tk
import random
import string
from zxcvbn import zxcvbn


VaultItem = namedtuple('VaultItem', ['identifier', 'username', 'notes', 'password'])

class VaultManager:
    DB_PATH = 'vault.db'

    def __init__(self):
        self.conn = None
        self.key = None
        self.salt = None

    def initialize(self, master_password: str):
        """ Initialize the vault, setting up database and deriving encryption key. """
        first_time = not os.path.exists(self.DB_PATH)
        self.conn = sqlite3.connect(self.DB_PATH)
        cursor = self.conn.cursor()

        if first_time:
            cursor.execute('''CREATE TABLE master_meta (salt BLOB NOT NULL)''')
            cursor.execute('''CREATE TABLE vault_items (
                identifier TEXT PRIMARY KEY,
                username TEXT,
                notes TEXT,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            )''')
            self.salt = os.urandom(16)
            cursor.execute("INSERT INTO master_meta (salt) VALUES (?)", (self.salt,))
            self.conn.commit()
        else:
            cursor.execute("SELECT salt FROM master_meta LIMIT 1")
            row = cursor.fetchone()
            if not row:
                raise Exception("Vault metadata missing; cannot derive key.")
            self.salt = row[0]

        
        raw_key = hash_secret(
            master_password.encode('utf-8'),
            self.salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        self.key = raw_key[-32:]

    def clear_sensitive(self):
        """ Clear sensitive data. """
        self.key = None
        if self.conn:
            self.conn.close()
            self.conn = None

    def load_items(self):
        """ Load all items from the vault and decrypt the passwords. """
        cursor = self.conn.cursor()
        cursor.execute("SELECT identifier, username, notes, nonce, tag, ciphertext FROM vault_items")
        items = []
        for ident, user, notes, nonce, tag, ct in cursor.fetchall():
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ct + tag, None).decode('utf-8')
            items.append(VaultItem(identifier=ident, username=user, notes=notes, password=plaintext))
        return items

    def prompt_new_item(self, root) -> dict:
        """ Prompt the user for details of a new vault item. """
        identifier = simpledialog.askstring("Input", "Enter identifier:", parent=root)
        if not identifier:
            return None
        username = simpledialog.askstring("Input", "Enter username/email:", parent=root)
        notes = simpledialog.askstring("Input", "Enter notes (optional):", parent=root)
        length = simpledialog.askinteger("Input", "Enter password length (8-64):", parent=root, minvalue=8, maxvalue=64)
        if not length:
            return None

        use_upper = messagebox.askyesno("Uppercase", "Include uppercase letters?", parent=root)
        use_lower = messagebox.askyesno("Lowercase", "Include lowercase letters?", parent=root)
        use_digits = messagebox.askyesno("Digits", "Include digits?", parent=root)
        use_symbols = messagebox.askyesno("Symbols", "Include symbols?", parent=root)

        return {
            'identifier': identifier.strip(),
            'username': username.strip() if username else None,
            'notes': notes.strip() if notes else None,
            'length': length,
            'use_upper': use_upper,
            'use_lower': use_lower,
            'use_digits': use_digits,
            'use_symbols': use_symbols
        }

    def generate_password(self, length, use_upper, use_lower, use_digits, use_symbols):
        """ Generate a random password with selected character sets. """
        chars = ''
        if use_upper: chars += string.ascii_uppercase
        if use_lower: chars += string.ascii_lowercase
        if use_digits: chars += string.digits
        if use_symbols: chars += string.punctuation
        if not chars:
            raise ValueError('No character sets selected')

        while True:
            pwd = ''.join(random.choice(chars) for _ in range(length))
            entropy = zxcvbn(pwd)['entropy']
            if entropy >= 60:
                return pwd

    def add_item(self, data: dict):
        """ Add a new item to the vault, encrypting the password. """
        pwd = self.generate_password(
            data['length'], data['use_upper'], data['use_lower'], data['use_digits'], data['use_symbols']
        )
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, pwd.encode('utf-8'), None)
        ct, tag = ciphertext[:-16], ciphertext[-16:]

        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO vault_items (identifier, username, notes, nonce, tag, ciphertext) VALUES (?, ?, ?, ?, ?, ?)",
            (data['identifier'], data['username'], data['notes'], nonce, tag, ct)
        )
        self.conn.commit()

    def delete_item(self, identifier: str):
        """ Delete an item from the vault. """
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM vault_items WHERE identifier=?", (identifier,))
        self.conn.commit()

    def get_decrypted_password(self, identifier: str) -> str:
        """ Retrieve and decrypt the password for a given identifier. """
        cursor = self.conn.cursor()
        cursor.execute("SELECT nonce, tag, ciphertext FROM vault_items WHERE identifier=?", (identifier,))
        row = cursor.fetchone()
        if not row:
            raise KeyError('Item not found')
        nonce, tag, ct = row
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ct + tag, None).decode('utf-8')

    def find_item(self, identifier: str):
        """ Find an item by identifier. """
        for item in self.load_items():
            if identifier.lower() in item.identifier.lower():
                return item
        return None

class VaultGUI:
    def __init__(self, master, manager):
        """ Initialize the GUI for managing the vault. """
        self.master = master
        self.master.title("Vault Manager")
        self.master.geometry("600x400")
        self.manager = manager

        self.item_listbox = tk.Listbox(self.master, width=50, height=15)
        self.item_listbox.pack(padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.master, orient='vertical', command=self.item_listbox.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.item_listbox.config(yscrollcommand=self.scrollbar.set)

        self.add_button = tk.Button(self.master, text="Add Item", command=self.add_item)
        self.add_button.pack(padx=10, pady=5)

        self.delete_button = tk.Button(self.master, text="Delete Item", command=self.delete_item)
        self.delete_button.pack(padx=10, pady=5)

        self.load_items()

    def load_items(self):
        """ Load all items from the vault and display them in the listbox. """
        self.item_listbox.delete(0, tk.END)
        items = self.manager.load_items()
        for item in items:
            display_text = f"{item.identifier} ({item.username})"
            self.item_listbox.insert(tk.END, display_text)

    def add_item(self):
        """ Prompt the user for new item details and add it to the vault. """
        data = self.manager.prompt_new_item(self.master)
        if data:
            self.manager.add_item(data)
            self.load_items()

    def delete_item(self):
        """ Delete the selected item from the vault. """
        selected_item_index = self.item_listbox.curselection()
        if not selected_item_index:
            messagebox.showwarning("No selection", "Please select an item to delete.")
            return

        selected_item_text = self.item_listbox.get(selected_item_index)
        identifier = selected_item_text.split('(')[0].strip()

        confirm = messagebox.askyesno("Delete Item", f"Are you sure you want to delete '{identifier}'?")
        if confirm:
            self.manager.delete_item(identifier)
            self.load_items()

    def run(self):
        """ Run the GUI application. """
        self.master.mainloop()

if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()
    manager = VaultManager()
    manager.initialize("your_master_password")
    app = VaultGUI(root, manager)
    app.run()
