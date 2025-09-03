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

- Python 3.9+ (Windows recommended, due to registry usage)  
- [PyInstaller](https://pyinstaller.org/)  
- [ttkbootstrap](https://pypi.org/project/ttkbootstrap/)  
- [PyArmor](https://github.com/dashingsoft/pyarmor) (**Required**)  
- Optional: [UPX](https://upx.github.io/) for additional packing

Install dependencies:

```bash
pip install pyinstaller pyarmor ttkbootstrap
