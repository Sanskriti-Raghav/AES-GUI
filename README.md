# 🔐 AES Encryption & Decryption with Tkinter GUI

This project is a simple **AES-128 encryption and decryption tool** built in Python with a user-friendly **Tkinter GUI**.  
It allows you to input plaintext, encrypt it into ciphertext (hex format), and decrypt it back into the original text.

---

## 🚀 Features
- AES-128 Encryption (with 16-byte key)
- AES-128 Decryption
- GUI built with Tkinter
- Error handling:
  - Wrong key size
  - Empty input
  - Invalid ciphertext format
- Default example key: `This is a key123`

---

## 📂 Project Structure
```
AES-GUI/
│
├── aes.py # AES implementation + Tkinter GUI
├── requirements.txt # Dependencies
├── README.md # Documentation
```

---

## ⚙️ Requirements

- Python 3.8+  
- Tkinter (comes pre-installed with Python in most systems)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the program with:
```
python aes.py
```
1. Enter your plaintext in the first box.
2. Enter a 16-byte key (default is already filled in).
3. Click Encrypt → Ciphertext will appear.
4. Click Decrypt → Decrypted text will appear.

---

## 🛡️ Notes
* Key must be exactly 16 bytes (AES-128).
* Ciphertext is displayed in hexadecimal format.
* Decryption works only with ciphertext produced by this program.

---