# Project_0-Secure_Login_Pretest

A hardened Python application designed with anti-debugging, anti-VM detection, brute-force resistance, and obfuscation.  
This project demonstrates how to build a secure GUI login system with registry-based credential storage and protective measures.

---

## 📂 Project Structure

- **`hook_antidebug.py`**  
  Detects debuggers and virtual machine environments. Exits if such conditions are detected.

- **`Project_0-Secure_Login_Pretest.py`**  
  Main application with the following features:
  - GUI login form (built with [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap))  
  - Strong password hashing with PBKDF2  
  - Registry-based user storage (to emulate a server-side blocklist)  
  - Account lockout and blocklist  
  - Protection against brute-force, reverse engineering, and static analysis

- **`Project_0-Secure_Login_Pretest.spec`**  
  PyInstaller spec file that defines how to package the app into an executable.

---

## 🛠️ Requirements

- Python 3.9+ (Windows recommended, due to registry usage but also because I made it only work in Windows, no Kali for you.)  
- [PyInstaller](https://pyinstaller.org/)  
- [ttkbootstrap](https://pypi.org/project/ttkbootstrap/)  
- [PyArmor](https://github.com/dashingsoft/pyarmor) 

Install dependencies:

```bash
pip install pyinstaller pyarmor ttkbootstrap
```

---

## 🔒 Obfuscation

Before building, you **must** obfuscate the code with PyArmor:

```bash
pyarmor gen Project_0-Secure_Login_Pretest.py --output dist-obf
```

If the terminal says that pyarmor does not exists or cannot find path use this command instead.
  
```bash
python -m pyarmor.cli gen Project_0-Secure_Login_Pretest.py --output dist-obf
```

This generates an obfuscated version of the code inside the `dist-obf/` directory.

---

## ⚙️ Building the Executable

Once obfuscated, package it with PyInstaller using the `.spec` file:

```bash
pyinstaller Project_0-Secure_Login_Pretest.spec
```

If the terminal says that pyinstaller does exists or cannot find path use this command instead.

```bash
python -m PyInstaller Project_0-Secure_Login_Pretest.spec
```

This includes the anti-debugging hook and bundles everything into an executable.

---

## 🚀 Running the App

After building, the executable will be located in the **`dist/`** folder.  
Run it by double-clicking or from the terminal:

```bash
dist/Project_0-Secure_Login_Pretest.exe
```

---

## ⚠️ Notes

- **Anti-Debug & Anti-VM**  
  The application will immediately exit if a debugger or virtual machine environment is detected.

- **Account Lockout**  
  Too many failed login attempts will block your user/device.  
  - If this happens during testing, you can manually unblock yourself:  
    1. Press **Win + R**, type `regedit`, and press Enter.  
    2. Navigate to the registry path used by the app and remove your entry from the **Blocked Users** list.  
    ⚠️ Only do this for testing. In a real deployment, blocked users would remain blocked on the server side, and you would need to implement a proper workaround similar to how they would be handled in production.

- **Testing Credentials**  
  - Default username: **`Mohg, Lord of Blood`**  
  - Default password: **`IOweUCookoutIGuess!23#`**

- **Paste Shortcut**  
  To simplify testing long credentials, you can temporarily enable copy–paste in the login fields with the shortcut: **Ctrl + Alt + P**.  
  - This is intended **only for ease of testing**. It would not exist in production-ready secure code.

- **Session Timeout**  
  Each login session is limited to **120 seconds** to reduce exposure to brute-force attempts.

---

## 📚 Libraries & References

Your project uses both **built-in Python standard libraries** and **third-party libraries**.  

### 🔹 Standard Libraries (included with Python)
- [sys](https://docs.python.org/3/library/sys.html) – System-specific parameters and functions (used for exiting, debugger detection).  
- [os](https://docs.python.org/3/library/os.html) – Operating system interfaces (used for generating salts, environment interaction).  
- [time](https://docs.python.org/3/library/time.html) – Time access and conversions (used for login delays).  
- [re](https://docs.python.org/3/library/re.html) – Regular expressions (used for validating usernames).  
- [hmac](https://docs.python.org/3/library/hmac.html) – Secure message authentication (used for constant-time password comparisons).  
- [hashlib](https://docs.python.org/3/library/hashlib.html) – Secure hash algorithms, including PBKDF2-HMAC.  
- [getpass](https://docs.python.org/3/library/getpass.html) – Get user login name (used in fingerprinting).  
- [socket](https://docs.python.org/3/library/socket.html) – Network interfaces (used for hostname retrieval).  
- [uuid](https://docs.python.org/3/library/uuid.html) – UUID and MAC address utilities.  
- [datetime](https://docs.python.org/3/library/datetime.html) – Date and time (used for credential creation timestamps).  
- [platform](https://docs.python.org/3/library/platform.html) – System platform information (used in VM detection).  
- [tkinter](https://docs.python.org/3/library/tkinter.html) – Standard GUI toolkit for Python.  
- [tkinter.messagebox](https://docs.python.org/3/library/tkinter.messagebox.html) – Pop-up message dialogs.  
- [winreg](https://docs.python.org/3/library/winreg.html) – Windows Registry access (used for user/blocklist storage).  

### 🔹 Third-Party Libraries
- [ttkbootstrap](https://ttkbootstrap.readthedocs.io/en/latest/) – A modern-themed wrapper around Tkinter’s `ttk` widgets for styled GUIs.  
- [PyInstaller](https://pyinstaller.org/en/stable/) – Freezes Python scripts into standalone executables; you used a `.spec` file to control build settings.  
- [PyArmor](https://github.com/dashingsoft/pyarmor) – Code obfuscation tool for protecting Python scripts.  
- [UPX](https://upx.github.io/) – (Optional) Ultimate Packer for Executables, used to compress your final binary.  
