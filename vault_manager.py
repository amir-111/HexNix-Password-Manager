# vault_manager.py

import os
import sqlite3
from collections import namedtuple
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import random
import string
from zxcvbn import zxcvbn
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import time


VaultItem = namedtuple('VaultItem', ['identifier', 'username', 'notes', 'password'])

class VaultManager:
    DB_PATH = 'vault.db'

    def __init__(self):
        self.conn = None
        self.key = None
        self.salt = None

    def initialize(self, master_password: str):
        first_time = not os.path.exists(self.DB_PATH)
        self.conn = sqlite3.connect(self.DB_PATH)
        cursor = self.conn.cursor()

        if first_time:
            cursor.execute('CREATE TABLE master_meta (salt BLOB NOT NULL)')
            cursor.execute('''
                CREATE TABLE vault_items (
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
            time_cost=3, memory_cost=65536,
            parallelism=4, hash_len=32,
            type=Type.ID
        )
        self.key = raw_key[-32:]

    def clear_sensitive(self):
        self.key = None
        if self.conn:
            self.conn.close()
            self.conn = None

    def load_items(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT identifier, username, notes, nonce, tag, ciphertext FROM vault_items")
        items = []
        for ident, user, notes, nonce, tag, ct in cursor.fetchall():
            aesgcm = AESGCM(self.key)
            pwd = aesgcm.decrypt(nonce, ct + tag, None).decode('utf-8')
            items.append(VaultItem(ident, user, notes, pwd))
        return items

    def prompt_new_item(self, parent):
        identifier = simpledialog.askstring("Identifier", "Enter identifier:", parent=parent)
        if not identifier: return None
        username = simpledialog.askstring("Username/Email", "Enter username/email:", parent=parent)
        notes    = simpledialog.askstring("Notes", "Enter notes (optional):", parent=parent)
        length   = simpledialog.askinteger("Password length", "Length (8–64):",
                                        parent=parent, minvalue=8, maxvalue=64)
        if not length: return None

        use_upper  = messagebox.askyesno("Uppercase?", "Include uppercase?", parent=parent)
        use_lower  = messagebox.askyesno("Lowercase?", "Include lowercase?", parent=parent)
        use_digits = messagebox.askyesno("Digits?", "Include digits?", parent=parent)
        use_symbols= messagebox.askyesno("Symbols?", "Include symbols?", parent=parent)

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
        chars = ''
        if use_upper:  chars += string.ascii_uppercase
        if use_lower:  chars += string.ascii_lowercase
        if use_digits: chars += string.digits
        if use_symbols:chars += string.punctuation
        if not chars:
            raise ValueError("No charset selected")

        max_tries = 500
        last_pwd = None
        for _ in range(max_tries):
            pwd = ''.join(random.choice(chars) for _ in range(length))
            last_pwd = pwd
            score = zxcvbn(pwd)
            if score.get('entropy', 0) >= 60:
                return pwd
        return last_pwd

    def add_item(self, data):
        pwd = self.generate_password(
            data['length'], data['use_upper'], data['use_lower'],
            data['use_digits'], data['use_symbols']
        )
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        cipher = aesgcm.encrypt(nonce, pwd.encode('utf-8'), None)
        ct, tag = cipher[:-16], cipher[-16:]

        c = self.conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO vault_items "
            "(identifier, username, notes, nonce, tag, ciphertext) VALUES (?,?,?,?,?,?)", 
            (data['identifier'], data['username'], data['notes'], nonce, tag, ct)
        )
        self.conn.commit()

    def delete_item(self, identifier):
        c = self.conn.cursor()
        c.execute("DELETE FROM vault_items WHERE identifier=?", (identifier,))
        self.conn.commit()

    def get_decrypted_password(self, identifier):
        c = self.conn.cursor()
        c.execute("SELECT nonce, tag, ciphertext FROM vault_items WHERE identifier=?", (identifier,))
        row = c.fetchone()
        if not row:
            raise KeyError("Item not found")
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(row[0], row[2] + row[1], None).decode('utf-8')

    def find_item(self, identifier):
        for itm in self.load_items():
            if identifier.lower() in itm.identifier.lower():
                return itm
        return None

class VaultGUI(tk.Tk):
    def __init__(self, vault_manager):
        super().__init__()
        self.manager = vault_manager
        self.title("Nemesis Vault Manager")
        self.geometry("800x600")

        self._build_ui()
        self.is_dark = True
        self._apply_theme()
        self._start_login()

    def _build_ui(self):
        toolbar = tk.Frame(self)
        toolbar.pack(fill=tk.X, pady=5)
        for txt, cmd in [("Add", self._prompt_add), ("Delete", self.delete_item),
                         ("Copy", self.copy_item), ("Search", self.search_item),
                         ("Theme", self.toggle_theme)]:
            tk.Button(toolbar, text=txt, command=cmd).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(self, columns=("ID","User","Notes"), show="headings")
        for col, heading in [("ID","Identifier"),("User","Username/Email"),("Notes","Notes")]:
            self.tree.heading(col, text=heading)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)

    def _apply_theme(self):
        bg = "#2b2b2b" if self.is_dark else "white"
        fg = "#f0f0f0" if self.is_dark else "black"
        self.configure(bg=bg)
        style = ttk.Style()
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg)
        style.configure("Treeview.Heading", background=bg, foreground=fg)

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self._apply_theme()

    def _start_login(self):
        def on_auth(pwd):
            try:
                self.manager.initialize(pwd)
                self._refresh_table()
            except Exception as e:
                messagebox.showerror("Unlock Failed", str(e))
                self.destroy()
        LoginDialog(self, on_auth)

    def _refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for itm in self.manager.load_items():
            self.tree.insert("", "end", values=(itm.identifier, itm.username or "", itm.notes or ""))

    def _prompt_add(self):
        data = self.manager.prompt_new_item(self)
        if not data:
            return
        self.manager.add_item(data)
        self._refresh_table()

    def delete_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Error","No selection")
            return
        ids = [self.tree.item(i)['values'][0] for i in sel]
        if messagebox.askyesno("Confirm","Delete %d item(s)?" % len(ids)):
            for i in ids:
                self.manager.delete_item(i)
            self._refresh_table()

    def copy_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Error","No selection")
            return
        pid = self.tree.item(sel[0])['values'][0]
        pwd = self.manager.get_decrypted_password(pid)
        self.clipboard_clear()
        self.clipboard_append(pwd)

    def search_item(self):
        key = simpledialog.askstring("Search","Identifier:", parent=self)
        if key:
            itm = self.manager.find_item(key)
            if itm:
                for r in self.tree.get_children(): self.tree.delete(r)
                self.tree.insert("", "end", values=(itm.identifier, itm.username or "", itm.notes or ""))
            else:
                messagebox.showinfo("Not Found","No match.")

class LoginDialog(tk.Toplevel):
    def __init__(self, parent, on_auth):
        super().__init__(parent)
        self.title("Unlock Vault")
        self.geometry("300x120")
        self.transient(parent)
        self.grab_set()
        self.on_auth = on_auth

        tk.Label(self, text="Master Password:").pack(pady=(10,0))
        self.pw = tk.Entry(self, show="*")
        self.pw.pack(pady=5); self.pw.focus()

        frm = tk.Frame(self)
        frm.pack(pady=5)
        tk.Button(frm, text="Unlock", command=self.try_unlock).pack(side=tk.LEFT, padx=5)
        tk.Button(frm, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def try_unlock(self):
        pwd = self.pw.get().strip()
        if not pwd:
            messagebox.showwarning("Error", "Enter password.")
            return
        self.on_auth(pwd)
        self.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    manager = VaultManager()
    app = VaultGUI(manager)
    root.mainloop()
