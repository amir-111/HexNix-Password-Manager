# gui.py

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import time

from vault_manager import VaultManager, VaultItem

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
        tk.Button(frm, text="Unlock",  command=self.try_unlock).pack(side=tk.LEFT, padx=5)
        tk.Button(frm, text="Cancel",  command=self.destroy).pack(side=tk.LEFT, padx=5)

    def try_unlock(self):
        pwd = self.pw.get().strip()
        if not pwd:
            messagebox.showwarning("Error", "Enter password.")
            return
        self.on_auth(pwd)
        self.destroy()

class VaultGUI:
    def __init__(self, master, manager: VaultManager):
        self.master  = master
        self.manager = manager
        master.title("Nemesis Vault Manager")
        master.geometry("800x600")

        self._build_ui()
        self.is_dark = True
        self._apply_theme()
        self._start_login()

    def _build_ui(self):
        toolbar = tk.Frame(self.master)
        toolbar.pack(fill=tk.X,pady=5)
        for txt, cmd in [("Add",self.add_item), ("Delete",self.delete_item),
                         ("Copy",self.copy_item),("Search",self.search_item),
                         ("Theme",self.toggle_theme)]:
            tk.Button(toolbar,text=txt,command=cmd).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(self.master, columns=("ID","User","Notes"), show="headings")
        for c,t in [("ID","Identifier"),("User","Username/Email"),("Notes","Notes")]:
            self.tree.heading(c,text=t)
        self.tree.pack(fill=tk.BOTH,expand=True, pady=5)

    def _apply_theme(self):
        bg = "#2b2b2b" if self.is_dark else "white"
        fg = "#f0f0f0" if self.is_dark else "black"
        self.master.configure(bg=bg)
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
                self.last_unlock = time.time()
            except Exception as e:
                messagebox.showerror("Unlock Failed", str(e))
                self.master.destroy()

        LoginDialog(self.master, on_auth)

    def _refresh_table(self):
        for r in self.tree.get_children(): self.tree.delete(r)
        for itm in self.manager.load_items():
            self.tree.insert("", "end", values=(itm.identifier, itm.username or "", itm.notes or ""))

    def add_item(self):
        data = self.manager.prompt_new_item(self.master)
        if data:
            self.manager.add_item(data)
            self._refresh_table()

    def delete_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Error","No selection")
            return
        ids = [self.tree.item(i)['values'][0] for i in sel]
        if messagebox.askyesno("Confirm","Delete %d item(s)?"%len(ids)):
            for i in ids: self.manager.delete_item(i)
            self._refresh_table()

    def copy_item(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Error","No selection")
            return
        pid = self.tree.item(sel[0])['values'][0]
        pwd = self.manager.get_decrypted_password(pid)
        self.master.clipboard_clear()
        self.master.clipboard_append(pwd)

    def search_item(self):
        key = simpledialog.askstring("Search","Identifier:",parent=self.master)
        if key:
            itm = self.manager.find_item(key)
            if itm:
                for r in self.tree.get_children(): self.tree.delete(r)
                self.tree.insert("", "end", values=(itm.identifier, itm.username or "", itm.notes or ""))
            else:
                messagebox.showinfo("Not Found","No match.")

if __name__ == '__main__':
    root = tk.Tk()
    manager = VaultManager()
    app = VaultGUI(root, manager)
    root.mainloop()
