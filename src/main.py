import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

from crpyto.playfair.playfair_chipher import *
from crpyto.polybius_square.polybius_square_chipher import *
from steganography.image import *
from crpyto.rsa.rsa_chipher import* 


# Create the main application window
root = tk.Tk()
root.title("Cryptography Project")
root.geometry("800x600")

# Create a Notebook widget for tabs
notebook = ttk.Notebook(root)

# Create frames for each tab
playfair_tab = ttk.Frame(notebook)

# Add a copy button to copy the result
def copy_result_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(playfair_result_text.get())
    root.update()  # Update the clipboard content
    messagebox.showinfo("Copied", "Result copied to clipboard!")

copy_button = ttk.Button(playfair_tab, text="Copy Result", command=copy_result_to_clipboard)
copy_button.grid(row=4, column=2, padx=10, pady=10, sticky="w")
polibuse_square_tab = ttk.Frame(notebook)

# Add Polybius Square tab
notebook.add(polibuse_square_tab, text="Polybuse Square")

# Add a copy button to copy the result
def copy_polybius_result_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(polybius_result_text.get())
    root.update()  # Update the clipboard content
    messagebox.showinfo("Copied", "Result copied to clipboard!")

copy_polybius_button = ttk.Button(polibuse_square_tab, text="Copy Result", command=copy_polybius_result_to_clipboard)
copy_polybius_button.grid(row=5, column=1, padx=10, pady=10, sticky="w")

# Add a dropdown to change Polybius Square configurations
def update_polybius_config(*args):
    selected_config = polybius_config_var.get()
    global polybius_config
    if selected_config == "Default":
        polybius_config = DefaultPolybiusSquareConfig()
    elif selected_config == "Use Null":
        polybius_config = UseNullPolybiusSquareConfig()
    elif selected_config == "No Null":
        polybius_config = NoNullPolybiusSquareConfig()

# Initialize with default configuration
polybius_config = DefaultPolybiusSquareConfig()

ttk.Label(polibuse_square_tab, text="Configuration:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
polybius_config_var = tk.StringVar(value="Default")
polybius_config_var.trace("w", update_polybius_config)
polybius_config_dropdown = ttk.Combobox(polibuse_square_tab, textvariable=polybius_config_var, values=["Default", "Use Null", "No Null"], state="readonly")
polybius_config_dropdown.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# Key input
ttk.Label(polibuse_square_tab, text="Key:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
polybius_key_entry = ttk.Entry(polibuse_square_tab, width=50)
polybius_key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# Plaintext/Ciphertext input
ttk.Label(polibuse_square_tab, text="Input Text:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
polybius_plaintext_entry = ttk.Entry(polibuse_square_tab, width=50)
polybius_plaintext_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Buttons
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

polybius_encrypt_button = ttk.Button(polibuse_square_tab, text="Encrypt", command=handle_polybius_encrypt)
polybius_encrypt_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

polybius_decrypt_button = ttk.Button(polibuse_square_tab, text="Decrypt", command=handle_polybius_decrypt)
polybius_decrypt_button.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Result output
ttk.Label(polibuse_square_tab, text="Result:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
polybius_result_text = tk.StringVar()
polybius_result_label = ttk.Label(polibuse_square_tab, textvariable=polybius_result_text, wraplength=600)
polybius_result_label.grid(row=4, column=1, padx=10, pady=10, sticky="w")
rsa_tab = ttk.Frame(notebook)
eas_tab = ttk.Frame(notebook)
steganography_tab = ttk.Frame(notebook)

# Add tabs to the notebook
notebook.add(playfair_tab, text="Playfair")
notebook.add(polibuse_square_tab, text="Polibuse Square")
# Add a dropdown to change Playfair configurations
def update_config(*args):
    selected_config = playfair_config_var.get()
    global playfair_config
    if selected_config == "Default":
        playfair_config = DefaultPlayfairConfig()
    elif selected_config == "Use Null":
        playfair_config = UseNullPlayfairConfig()
    elif selected_config == "No Null":
        playfair_config = NoNullPlayfairConfig()

# Initialize with default configuration
playfair_config = DefaultPlayfairConfig()

ttk.Label(playfair_tab, text="Configuration:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
playfair_config_var = tk.StringVar(value="Default")
playfair_config_var.trace("w", update_config)
playfair_config_dropdown = ttk.Combobox(playfair_tab, textvariable=playfair_config_var, values=["Default", "Use Null", "No Null"], state="readonly")
playfair_config_dropdown.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Update encrypt and decrypt to use the selected configuration
def handle_encrypt():
    key = playfair_key_entry.get()
    plaintext = playfair_plaintext_entry.get()
    if not key or not plaintext:
        messagebox.showerror("Error", "Key and plaintext cannot be empty!")
        return
    try:
        cipher = PlayfairCipher(key, playfair_config)
        encrypted_text = cipher.encrypt(plaintext)
        playfair_result_text.set(encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_decrypt():
    key = playfair_key_entry.get()
    ciphertext = playfair_plaintext_entry.get()
    if not key or not ciphertext:
        messagebox.showerror("Error", "Key and ciphertext cannot be empty!")
        return
    try:
        cipher = PlayfairCipher(key, playfair_config)
        decrypted_text = cipher.decrypt(ciphertext)
        playfair_result_text.set(decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))
notebook.add(rsa_tab, text="RSA")
notebook.add(eas_tab, text="EAS")
# Add Steganography tab
notebook.add(steganography_tab, text="Steganography")

# Steganography Tab UI
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
        decoded_data = steganography.decode(file_path, output_path=steganography_output_path_entry.get())
        steganography_result_text.set(decoded_data)
        print(decoded_data)
        messagebox.showinfo("Success", "Data decoded successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Input fields for Steganography
ttk.Label(steganography_tab, text="Data to Encode:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
steganography_data_entry = ttk.Entry(steganography_tab, width=50)
steganography_data_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

ttk.Label(steganography_tab, text="File Path:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
steganography_file_path_entry = ttk.Entry(steganography_tab, width=50)
steganography_file_path_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

ttk.Label(steganography_tab, text="Output Path:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
steganography_output_path_entry = ttk.Entry(steganography_tab, width=50)
steganography_output_path_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Buttons for Steganography
steganography_encode_button = ttk.Button(steganography_tab, text="Encode", command=handle_encode)
steganography_encode_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

steganography_decode_button = ttk.Button(steganography_tab, text="Decode", command=handle_decode)
steganography_decode_button.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Result output for Steganography
ttk.Label(steganography_tab, text="Decoded Result:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
steganography_result_text = tk.StringVar()
steganography_result_label = ttk.Label(steganography_tab, textvariable=steganography_result_text, wraplength=600)
steganography_result_label.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Pack the notebook into the main window
notebook.pack(expand=True, fill="both")

# Playfair Tab UI
def handle_encrypt():
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

def handle_decrypt():
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

# Key input
ttk.Label(playfair_tab, text="Key:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
playfair_key_entry = ttk.Entry(playfair_tab, width=50)
playfair_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# Plaintext/Ciphertext input
ttk.Label(playfair_tab, text="Input Text:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
playfair_plaintext_entry = ttk.Entry(playfair_tab, width=50)
playfair_plaintext_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# Buttons
playfair_encrypt_button = ttk.Button(playfair_tab, text="Encrypt", command=handle_encrypt)
playfair_encrypt_button.grid(row=2, column=0, padx=10, pady=10, sticky="w")

playfair_decrypt_button = ttk.Button(playfair_tab, text="Decrypt", command=handle_decrypt)
playfair_decrypt_button.grid(row=2, column=1, padx=10, pady=10, sticky="w")

# Result output
ttk.Label(playfair_tab, text="Result:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
playfair_result_text = tk.StringVar()
playfair_result_label = ttk.Label(playfair_tab, textvariable=playfair_result_text, wraplength=600)
playfair_result_label.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Run the application
root.mainloop()