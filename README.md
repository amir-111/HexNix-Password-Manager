HexNix Password Manager

> “We redefine security through code.”

*Developed and maintained by the -HexNix- Team*

---

🎯 Project Objective
An offline, encrypted password manager built on AES-GCM and Argon2, designed to deliver a simple yet professional user experience.

---

📂 Code Structure

- vault_manager.py 
  - Class: `VaultManager`  
    - `initialize(master_password)`  
    - `add_item(identifier, username, notes, length, use_upper, use_lower, use_digits, use_symbols)`  
    - `delete_item(identifier)`  
    - `get_password(identifier)`  
    - `load_items()`  
  - Implements Argon2 key derivation, AES-GCM encryption, and SQLite storage.

- gui.py  
  - *Class*: `VaultGUI` (Tkinter + ttkbootstrap)  
    - Buttons: *Add*, *Delete*, *Copy*, *Search*, *Theme* 
    - Uses `simpledialog` for input forms  
    - Renders and refreshes the password list in a table view

- **MAIN.py**  
  - Entry point for the application:  
    ```python
    from gui import start_app

    if __name__ == "__main__":
        start_app()
    ```

---

🚀 How to Use the Code

1. Invoke `start_app()` in `MAIN.py` to launch the GUI.  
2. Inside the GUI:
   - *initialize(master_password)* → Creates or unlocks the local database.  
   - *Add* → Open form to create a new password entry.  
   - *Delete* → Remove the selected entry.  
   - *Copy* → Copy the chosen password to your clipboard.  
   - *Search* → Quickly filter entries by identifier.  
   - *Theme* → Toggle between light and dark modes.  
3. All operations run completely offline—no internet connection required.

---

> HexNix Team
> Discover the true power of software through simplicity and security.
> T.me/amircg2
