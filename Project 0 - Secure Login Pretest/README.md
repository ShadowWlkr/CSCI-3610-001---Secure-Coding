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
- [PyArmor](https://github.com/dashingsoft/pyarmor) (**Required**)  
- Optional: [UPX](https://upx.github.io/) for additional packing

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

This generates an obfuscated version of the code inside the `dist-obf/` directory.

---

## ⚙️ Building the Executable

Once obfuscated, package it with PyInstaller using the `.spec` file:

```bash
pyinstaller Project_0-Secure_Login_Pretest.spec
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
