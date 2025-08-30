import tkinter as tk
from tkinter import messagebox, scrolledtext

# =============================
# AES CLASS IMPLEMENTATION
# =============================

# AES S-Box (256 elements)
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-Box
INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i

# Round constants
RCON = [
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
]

class AES:
    def __init__(self, key):
        assert len(key) == 16, "Key must be 16 bytes long for AES-128"
        self.Nr = 10
        self.key_schedule = self._expand_key(key)

    def _expand_key(self, key):
        key_columns = [list(key[i:i+4]) for i in range(0, 16, 4)]
        for i in range(4, 4 * (self.Nr + 1)):
            temp = key_columns[i - 1][:]
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                temp = [S_BOX[b] for b in temp]
                temp = [t ^ r for t, r in zip(temp, RCON[(i // 4) - 1])]
            key_columns.append([b1 ^ b2 for b1, b2 in zip(temp, key_columns[i - 4])])
        return [key_columns[4*i:4*(i+1)] for i in range(self.Nr + 1)]

    def _add_round_key(self, state, round_key):
        return [[s ^ rk for s, rk in zip(col, round_key[i])] for i, col in enumerate(state)]

    def _sub_bytes(self, state):
        return [[S_BOX[b] for b in col] for col in state]

    def _inv_sub_bytes(self, state):
        return [[INV_S_BOX[b] for b in col] for col in state]

    def _shift_rows(self, state):
        rows = list(zip(*state))
        for i in range(1, 4):
            rows[i] = rows[i][i:] + rows[i][:i]
        return [list(col) for col in zip(*rows)]

    def _inv_shift_rows(self, state):
        rows = list(zip(*state))
        for i in range(1, 4):
            rows[i] = rows[i][-i:] + rows[i][:-i]
        return [list(col) for col in zip(*rows)]

    def _mix_columns(self, state):
        # Skipped for simplicity
        return state

    def _inv_mix_columns(self, state):
        # Skipped for simplicity
        return state

    def _bytes_to_matrix(self, text):
        return [list(text[i::4]) for i in range(4)]

    def _matrix_to_bytes(self, matrix):
        return bytes(sum(zip(*matrix), ()))

    def encrypt(self, plaintext):
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)
        ciphertext = b""
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            state = self._bytes_to_matrix(block)
            state = self._add_round_key(state, self.key_schedule[0])
            for round in range(1, self.Nr):
                state = self._sub_bytes(state)
                state = self._shift_rows(state)
                state = self._mix_columns(state)
                state = self._add_round_key(state, self.key_schedule[round])
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._add_round_key(state, self.key_schedule[self.Nr])
            ciphertext += self._matrix_to_bytes(state)
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            state = self._bytes_to_matrix(block)
            state = self._add_round_key(state, self.key_schedule[self.Nr])
            for round in range(self.Nr - 1, 0, -1):
                state = self._inv_shift_rows(state)
                state = self._inv_sub_bytes(state)
                state = self._add_round_key(state, self.key_schedule[round])
                state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.key_schedule[0])
            plaintext += self._matrix_to_bytes(state)
        padding_length = plaintext[-1]
        return plaintext[:-padding_length]


# =============================
# TKINTER GUI APP
# =============================

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.geometry("600x500")
        self.root.configure(bg="#f4f6f7")

        tk.Label(root, text="AES Encryption & Decryption", 
                 font=("Arial", 18, "bold"), bg="#34495e", fg="white", pady=10).pack(fill="x")

        tk.Label(root, text="Plaintext:", font=("Arial", 12), bg="#f4f6f7").pack(anchor="w", padx=20, pady=(15, 0))
        self.plaintext_entry = scrolledtext.ScrolledText(root, height=4, width=60, font=("Consolas", 11))
        self.plaintext_entry.pack(padx=20, pady=5)

        tk.Label(root, text="Key (16 bytes):", font=("Arial", 12), bg="#f4f6f7").pack(anchor="w", padx=20, pady=(10, 0))
        self.key_entry = tk.Entry(root, width=50, font=("Consolas", 11), show="*")
        self.key_entry.insert(0, "This is a key123")  # default key
        self.key_entry.pack(padx=20, pady=5)

        button_frame = tk.Frame(root, bg="#f4f6f7")
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Encrypt", command=self.encrypt, width=15, bg="#27ae60", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Decrypt", command=self.decrypt, width=15, bg="#2980b9", fg="white").grid(row=0, column=1, padx=10)

        tk.Label(root, text="Ciphertext (Hex):", font=("Arial", 12), bg="#f4f6f7").pack(anchor="w", padx=20, pady=(15, 0))
        self.ciphertext_entry = scrolledtext.ScrolledText(root, height=4, width=60, font=("Consolas", 11))
        self.ciphertext_entry.pack(padx=20, pady=5)

        tk.Label(root, text="Decrypted Text:", font=("Arial", 12), bg="#f4f6f7").pack(anchor="w", padx=20, pady=(15, 0))
        self.decrypted_entry = scrolledtext.ScrolledText(root, height=4, width=60, font=("Consolas", 11))
        self.decrypted_entry.pack(padx=20, pady=5)

    def get_key(self):
        key = self.key_entry.get().encode("utf-8")
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be exactly 16 bytes long!")
            return None
        return key

    def encrypt(self):
        key = self.get_key()
        if not key:
            return
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip().encode("utf-8")
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter plaintext!")
            return

        aes = AES(key)
        ciphertext = aes.encrypt(plaintext)
        self.ciphertext_entry.delete("1.0", tk.END)
        self.ciphertext_entry.insert(tk.END, ciphertext.hex())

    def decrypt(self):
        key = self.get_key()
        if not key:
            return
        ciphertext_hex = self.ciphertext_entry.get("1.0", tk.END).strip()
        if not ciphertext_hex:
            messagebox.showwarning("Warning", "Please enter ciphertext in hex format!")
            return

        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid ciphertext hex format!")
            return

        aes = AES(key)
        decrypted = aes.decrypt(ciphertext)
        self.decrypted_entry.delete("1.0", tk.END)
        self.decrypted_entry.insert(tk.END, decrypted.decode("utf-8", errors="ignore"))


# =============================
# RUN GUI
# =============================
if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
