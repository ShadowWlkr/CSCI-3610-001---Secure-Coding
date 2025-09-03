# Project_0-Secure_Login_Pretest

A hardened Python application designed with anti-debugging, anti-VM detection, brute-force resistance, and obfuscation.  
This project demonstrates how to build a secure GUI login system with registry-based credential storage and protective measures.

---

## 📂 Project Structure

- **`hook_antidebug.py`**  
  Hook script that detects debuggers and virtual machine environments. Exits if such conditions are detected.

- **`Project_0-Secure_Login_Pretest.py`**  
  Main application.  
  Features:
  - GUI login form (built with [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap))  
  - Strong password hashing with PBKDF2  
  - Registry-based user storage to emulate server-side blocklist 
  - Account lockout and blocklist  
  - Protection against brute-force, reverse engineering, and static analysis

- **`Project_0-Secure_Login_Pretest.spec`**  
  PyInstaller spec file that defines how to package the app into an executable.

---

## 🛠️ Requirements

- Python 3.9+ (Windows recommended, due to registry usage)
- [PyInstaller](https://pyinstaller.org/)  
- [ttkbootstrap](https://pypi.org/project/ttkbootstrap/)  
- [PyArmor](https://github.com/dashingsoft/pyarmor) (**Required**)  
- Optional (for extra packing): [UPX](https://upx.github.io/)

Install dependencies:

```bash
pip install pyinstaller pyarmor ttkbootstrap
```

---

## 🔒 Obfuscation (Required Step)

Before building, you **must** obfuscate the code with PyArmor:

```bash
pyarmor gen Project_0-Secure_Login_Pretest.py --output dist-obf
```

This generates an obfuscated version of the code inside `dist-obf/`.

---

## ⚙️ Building the Executable

Once obfuscated, package it with PyInstaller using the `.spec` file:

```bash
pyinstaller Project_0-Secure_Login_Pretest.spec
```

This will include the anti-debugging hook and bundle everything into an EXE.

---

## 🚀 Running the App

After building, the executable will be located in the **`dist/`** folder.  
Run it by double-clicking or from the terminal:

```bash
dist/Project_0-Secure_Login_Pretest.exe
```

---

## ⚠️ Notes

- Running inside a VM or with a debugger will cause the program to exit immediately.  
- Too many failed login attempts will block your user/device.  
- For testing:  
  - Default credentials are defined in the source (`CORRECT_USERNAME`, `CORRECT_PASSWORD`).  
- Session is limited to **120 seconds** for security.  
