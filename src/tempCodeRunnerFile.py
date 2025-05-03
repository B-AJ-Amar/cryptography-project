import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

from crpyto.playfair.playfair_chipher import *
from crpyto.polybius_square.polybius_square_chipher import *
from steganography.image import *
from crpyto.rsa.rsa_cipher import *

# main application window
root = tk.Tk()
root.title("Cryptography Project")
root.geometry("800x600")

# notebook widget for tabs
notebook = ttk.Notebook(root)

# frames for each tab
playfair_tab = ttk.Frame(notebook)
polybius_square_tab = ttk.Frame(notebook)
rsa_tab = ttk.Frame(notebook)
eas_tab = ttk.Frame(notebook)
steganography_tab = ttk.Frame(notebook)

# ===== Playfair Tab =====
# key input
ttk.Label(playfair_tab, text="Key:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
playfair_key_entry = ttk.Entry(playfair_tab, width=50)
playfair_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# plaintext/ciphertext input
ttk.Label(playfair_tab, text="Input Text:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
playfair_plaintext_entry = ttk.Entry(playfair_tab, width=50)
playfair_plaintext_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# buttons
def handle_playfair_encrypt():
    key = playfair_key_entry.get()
    plaintext = playfair_plaintext_entry.get()
    if not key or not plaintext:
        messagebox.showerror("Error", "Key and plaintext cannot be empty!")
        return
    try:
        cipher = PlayfairCipher(key)
        encrypted_text = cipher.encrypt(plaintext)
        playfair_result_text.set(encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_playfair_decrypt():
    key = playfair_key_entry.get()
    ciphertext = playfair_plaintext_entry.get()
    if not key or not ciphertext:
        messagebox.showerror("Error", "Key and ciphertext cannot be empty!")
        return
    try:
        cipher = PlayfairCipher(key)
        decrypted_text = cipher.decrypt(ciphertext)
        playfair_result_text.set(decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

playfair_encrypt_button = ttk.Button(playfair_tab, text="Encrypt", command=handle_playfair_encrypt)
playfair_encrypt_button.grid(row=2, column=0, padx=10, pady=10, sticky="w")

playfair_decrypt_button = ttk.Button(playfair_tab, text="Decrypt", command=handle_playfair_decrypt)
playfair_decrypt_button.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# result output
ttk.Label(playfair_tab, text="Result:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
playfair_result_text = tk.StringVar()
playfair_result_label = ttk.Label(playfair_tab, textvariable=playfair_result_text, wraplength=600)
playfair_result_label.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# copy button
def copy_playfair_result():
    root.clipboard_clear()
    root.clipboard_append(playfair_result_text.get())
    root.update()
    messagebox.showinfo("Copied", "Result copied to clipboard!")

copy_playfair_button = ttk.Button(playfair_tab, text="Copy Result", command=copy_playfair_result)
copy_playfair_button.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# ===== Polybius Square Tab =====
# configuration dropdown
def update_polybius_config(*args):
    selected_config = polybius_config_var.get()
    global polybius_config
    if selected_config == "Default":
        polybius_config = DefaultPolybiusSquareConfig()
    elif selected_config == "Use Null":
        polybius_config = UseNullPolybiusSquareConfig()
    elif selected_config == "No Null":
        polybius_config = NoNullPolybiusSquareConfig()

polybius_config = DefaultPolybiusSquareConfig()

ttk.Label(polybius_square_tab, text="Configuration:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
polybius_config_var = tk.StringVar(value="Default")
polybius_config_var.trace("w", update_polybius_config)
polybius_config_dropdown = ttk.Combobox(polybius_square_tab, textvariable=polybius_config_var, 
                                      values=["Default", "Use Null", "No Null"], state="readonly")
polybius_config_dropdown.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# key input
ttk.Label(polybius_square_tab, text="Key:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
polybius_key_entry = ttk.Entry(polybius_square_tab, width=50)
polybius_key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# plaintext/Ciphertext input
ttk.Label(polybius_square_tab, text="Input Text:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
polybius_plaintext_entry = ttk.Entry(polybius_square_tab, width=50)
polybius_plaintext_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# buttons
def handle_polybius_encrypt():
    key = polybius_key_entry.get()
    plaintext = polybius_plaintext_entry.get()
    if not key or not plaintext:
        messagebox.showerror("Error", "Key and plaintext cannot be empty!")
        return
    try:
        cipher = PolybiusSquareCipher(key, polybius_config)
        encrypted_text = cipher.encrypt(plaintext)
        polybius_result_text.set(encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_polybius_decrypt():
    key = polybius_key_entry.get()
    ciphertext = polybius_plaintext_entry.get()
    if not key or not ciphertext:
        messagebox.showerror("Error", "Key and ciphertext cannot be empty!")
        return
    try:
        cipher = PolybiusSquareCipher(key, polybius_config)
        decrypted_text = cipher.decrypt(ciphertext)
        polybius_result_text.set(decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

polybius_encrypt_button = ttk.Button(polybius_square_tab, text="Encrypt", command=handle_polybius_encrypt)
polybius_encrypt_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

polybius_decrypt_button = ttk.Button(polybius_square_tab, text="Decrypt", command=handle_polybius_decrypt)
polybius_decrypt_button.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# result output
ttk.Label(polybius_square_tab, text="Result:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
polybius_result_text = tk.StringVar()
polybius_result_label = ttk.Label(polybius_square_tab, textvariable=polybius_result_text, wraplength=600)
polybius_result_label.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# copy button
def copy_polybius_result():
    root.clipboard_clear()
    root.clipboard_append(polybius_result_text.get())
    root.update()
    messagebox.showinfo("Copied", "Result copied to clipboard!")

copy_polybius_button = ttk.Button(polybius_square_tab, text="Copy Result", command=copy_polybius_result)
copy_polybius_button.grid(row=5, column=1, padx=10, pady=10, sticky="w")

# ===== RSA Tab =====
# key inputs frame
rsa_key_frame = ttk.LabelFrame(rsa_tab, text="RSA Keys", padding=10)
rsa_key_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# public Key
ttk.Label(rsa_key_frame, text="Public Key (n,e):").grid(row=0, column=0, padx=5, pady=2, sticky="w")
rsa_public_key_entry = ttk.Entry(rsa_key_frame, width=70)
rsa_public_key_entry.grid(row=0, column=1, padx=5, pady=2, sticky="w")

# private Key
ttk.Label(rsa_key_frame, text="Private Key (n,d):").grid(row=1, column=0, padx=5, pady=2, sticky="w")
rsa_private_key_entry = ttk.Entry(rsa_key_frame, width=70)
rsa_private_key_entry.grid(row=1, column=1, padx=5, pady=2, sticky="w")

# key buttons frame
rsa_key_button_frame = ttk.Frame(rsa_key_frame)
rsa_key_button_frame.grid(row=2, column=0, columnspan=2, pady=5)

def generate_rsa_keys():
    try:
        rsa = RSA_Cipher(key_size=2048)
        public_key, private_key = rsa.public_key, rsa.private_key
        
        rsa_public_key_entry.delete(0, tk.END)
        rsa_public_key_entry.insert(0, public_key)
        rsa_private_key_entry.delete(0, tk.END)
        rsa_private_key_entry.insert(0, private_key)
        
        n, e = rsa._parse_key(public_key)
        messagebox.showinfo(
            "Keys Generated", 
            f"RSA-{n.bit_length()} keys generated:\n\n"
            f"Public: (n={str(n)[:20]}..., e={e})\n"
            f"Private: (n={str(n)[:20]}..., d=...)"
        )
        update_rsa_buttons()
    except Exception as e:
        messagebox.showerror("Key Generation Failed", str(e))

def verify_rsa_keys():
    public_key = rsa_public_key_entry.get()
    private_key = rsa_private_key_entry.get()
    
    if not public_key and not private_key:
        messagebox.showinfo("No Keys", "Please enter keys to verify")
        return
    
    try:
        messages = []
        if public_key:
            n_pub, e = RSA_Cipher()._parse_key(public_key)
            messages.append(f"Public Key Valid\nn: {str(n_pub)[:50]}...\ne: {e}")
        
        if private_key:
            n_priv, d = RSA_Cipher()._parse_key(private_key)
            messages.append(f"Private Key Valid\nn: {str(n_priv)[:50]}...\nd: ...")
        
        if public_key and private_key:
            if n_pub != n_priv:
                messages.append("⚠️ Warning: Public and private keys don't match!")
            else:
                messages.append("✓ Key pair is valid and matched")
        
        messagebox.showinfo("Key Verification", "\n\n".join(messages))
    except Exception as e:
        messagebox.showerror("Invalid Key Format", str(e))

ttk.Button(rsa_key_button_frame, text="Generate Keys", command=generate_rsa_keys).grid(row=0, column=0, padx=5)
ttk.Button(rsa_key_button_frame, text="Verify Keys", command=verify_rsa_keys).grid(row=0, column=1, padx=5)

# input/output frame
rsa_io_frame = ttk.LabelFrame(rsa_tab, text="Encryption/Decryption", padding=10)
rsa_io_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

# Input
ttk.Label(rsa_io_frame, text="Input Text:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
rsa_input_entry = ttk.Entry(rsa_io_frame, width=70)
rsa_input_entry.grid(row=0, column=1, padx=5, pady=2, sticky="w")

# buttons
def handle_rsa_encrypt():
    public_key = rsa_public_key_entry.get()
    plaintext = rsa_input_entry.get()
    
    if not public_key:
        messagebox.showerror("Error", "Public key is required for encryption!")
        return
    if not plaintext:
        messagebox.showerror("Error", "Plaintext cannot be empty!")
        return
    
    try:
        rsa = RSA_Cipher(public_key=public_key)
        ciphertext = rsa.encrypt(plaintext)
        rsa_result_text.delete(1.0, tk.END)
        rsa_result_text.insert(tk.END, ciphertext)
    except Exception as e:
        messagebox.showerror("Encryption Failed", str(e))

def handle_rsa_decrypt():
    private_key = rsa_private_key_entry.get()
    ciphertext = rsa_input_entry.get()
    
    if not private_key:
        messagebox.showerror("Error", "Private key is required for decryption!")
        return
    if not ciphertext:
        messagebox.showerror("Error", "Ciphertext cannot be empty!")
        return
    
    try:
        rsa = RSA_Cipher(private_key=private_key)
        plaintext = rsa.decrypt(ciphertext)
        rsa_result_text.delete(1.0, tk.END)
        rsa_result_text.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

rsa_button_frame = ttk.Frame(rsa_io_frame)
rsa_button_frame.grid(row=1, column=0, columnspan=2, pady=5)

rsa_encrypt_button = ttk.Button(rsa_button_frame, text="Encrypt", command=handle_rsa_encrypt, state=tk.DISABLED)
rsa_encrypt_button.grid(row=0, column=0, padx=5)

rsa_decrypt_button = ttk.Button(rsa_button_frame, text="Decrypt", command=handle_rsa_decrypt, state=tk.DISABLED)
rsa_decrypt_button.grid(row=0, column=1, padx=5)

# result
ttk.Label(rsa_io_frame, text="Result:").grid(row=2, column=0, padx=5, pady=2, sticky="nw")
rsa_result_text = tk.Text(rsa_io_frame, wrap=tk.WORD, width=60, height=8)
rsa_result_text.grid(row=2, column=1, padx=5, pady=2, sticky="w")

# copy button
def copy_rsa_result():
    result = rsa_result_text.get(1.0, tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!")
    else:
        messagebox.showwarning("Empty", "No result to copy")

ttk.Button(rsa_io_frame, text="Copy Result", command=copy_rsa_result).grid(row=3, column=1, pady=5, sticky="e")

# UI 
def update_rsa_buttons():
    public_key = rsa_public_key_entry.get().strip()
    private_key = rsa_private_key_entry.get().strip()
    input_text = rsa_input_entry.get().strip()
    
    rsa_encrypt_button.config(state=tk.NORMAL if (public_key and input_text) else tk.DISABLED)
    rsa_decrypt_button.config(state=tk.NORMAL if (private_key and input_text) else tk.DISABLED)

rsa_public_key_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())
rsa_private_key_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())
rsa_input_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())

# initialize button states
update_rsa_buttons()

# ===== Steganography Tab =====
# input fields
ttk.Label(steganography_tab, text="Data to Encode:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
steganography_data_entry = ttk.Entry(steganography_tab, width=50)
steganography_data_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

ttk.Label(steganography_tab, text="File Path:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
steganography_file_path_entry = ttk.Entry(steganography_tab, width=50)
steganography_file_path_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

ttk.Label(steganography_tab, text="Output Path:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
steganography_output_path_entry = ttk.Entry(steganography_tab, width=50)
steganography_output_path_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# buttons
def handle_encode():
    data = steganography_data_entry.get()
    file_path = steganography_file_path_entry.get()
    output_path = steganography_output_path_entry.get()
    if not data or not file_path or not output_path:
        messagebox.showerror("Error", "All fields must be filled!")
        return
    try:
        steganography = SteganographyLSBImage()
        steganography.encode(data, file_path, output_path)
        messagebox.showinfo("Success", "Data encoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_decode():
    file_path = steganography_file_path_entry.get()
    output_path = steganography_output_path_entry.get()
    if not file_path:
        messagebox.showerror("Error", "File path cannot be empty!")
        return
    try:
        steganography = SteganographyLSBImage()
        decoded_data = steganography.decode(file_path, output_path=output_path)
        steganography_result_text.set(decoded_data)
        messagebox.showinfo("Success", "Data decoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

steganography_encode_button = ttk.Button(steganography_tab, text="Encode", command=handle_encode)
steganography_encode_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

steganography_decode_button = ttk.Button(steganography_tab, text="Decode", command=handle_decode)
steganography_decode_button.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# result output
ttk.Label(steganography_tab, text="Decoded Result:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
steganography_result_text = tk.StringVar()
steganography_result_label = ttk.Label(steganography_tab, textvariable=steganography_result_text, wraplength=600)
steganography_result_label.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# ===== EAS Tab (Placeholder) =====
ttk.Label(eas_tab, text="EAS Cipher - To be implemented").pack(pady=50)

# add all tabs to the notebook
notebook.add(playfair_tab, text="Playfair")
notebook.add(polybius_square_tab, text="Polybius Square")
notebook.add(rsa_tab, text="RSA")
notebook.add(eas_tab, text="EAS")
notebook.add(steganography_tab, text="Steganography")

# pack notebook into the main window
notebook.pack(expand=True, fill="both")

root.mainloop()