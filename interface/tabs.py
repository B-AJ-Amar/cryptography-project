import tkinter as tk
from tkinter import ttk, messagebox
import base64

# --- Encryption/Decryption Functions ---

def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def reverse_encrypt(text):
    return text[::-1]

def reverse_decrypt(text):
    return text[::-1]

def vigenere_encrypt(text, key):
    key = key.lower()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.lower()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def base64_decrypt(text):
    try:
        return base64.b64decode(text.encode()).decode()
    except Exception:
        return "Invalid base64 input!"

# --- UI Functions ---

def create_tab(tab_control, name, encrypt_func, decrypt_func, needs_key=False):
    tab = ttk.Frame(tab_control)
    tab_control.add(tab, text=name)

    ttk.Label(tab, text="Enter Plain Text:").pack(pady=5)
    input_text = tk.Text(tab, height=4, width=50)
    input_text.pack()

    key_entry = None
    if needs_key:
        ttk.Label(tab, text="Enter Key:").pack(pady=5)
        key_entry = tk.Entry(tab, width=30)
        key_entry.pack()

    result_label = ttk.Label(tab, text="Result: ", foreground="blue")
    result_label.pack(pady=10)

    def on_encrypt():
        text = input_text.get("1.0", "end").strip()
        key = key_entry.get().strip() if needs_key else None
        if needs_key and not key:
            messagebox.showerror("Missing Key", "Please enter a key.")
            return
        result = encrypt_func(text, key) if key else encrypt_func(text)
        result_label.config(text=f"Encrypted: {result}")

    def on_decrypt():
        text = input_text.get("1.0", "end").strip()
        key = key_entry.get().strip() if needs_key else None
        if needs_key and not key:
            messagebox.showerror("Missing Key", "Please enter a key.")
            return
        result = decrypt_func(text, key) if key else decrypt_func(text)
        result_label.config(text=f"Decrypted: {result}")

    ttk.Button(tab, text="Encrypt", command=on_encrypt).pack(pady=5)
    ttk.Button(tab, text="Decrypt", command=on_decrypt).pack()

# --- Main App ---

root = tk.Tk()
root.title("Cryptography Toolkit")
root.geometry("650x400")

tab_control = ttk.Notebook(root)

# Tabs
create_tab(tab_control, "Caesar Cipher", caesar_encrypt, caesar_decrypt)
create_tab(tab_control, "Vigenère Cipher", vigenere_encrypt, vigenere_decrypt, needs_key=True)
create_tab(tab_control, "Reverse Cipher", reverse_encrypt, reverse_decrypt)
create_tab(tab_control, "Base64", base64_encrypt, base64_decrypt)

tab_control.pack(expand=1, fill="both")

root.mainloop()
