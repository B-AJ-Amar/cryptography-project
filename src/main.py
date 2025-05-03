import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.font import Font

# Import your cipher modules
from crpyto.playfair.playfair_chipher import (
    DefaultPlayfairConfig,
    UseNullPlayfairConfig,
    NoNullPlayfairConfig,
    PlayfairCipher
)
from crpyto.polybius_square.polybius_square_chipher import (
    DefaultPolybiusSquareConfig,
    UseNullPolybiusSquareConfig,
    NoNullPolybiusSquareConfig,
    PolybiusSquareCipher
)
from crpyto.rsa.rsa_cipher import RSA_Cipher
from steganography.image import SteganographyLSBImage

from crpyto.AES.aes import *

# Custom color scheme
COLORS = {
    'background': '#2d2d2d',
    'foreground': '#e0e0e0',
    'accent': '#4a6fa5',
    'secondary': '#3a3a3a',
    'text': '#ffffff',
    'entry_bg': '#3a3a3a',
    'entry_fg': '#ffffff',
    'button_active': '#5a8fd8',
    'success': '#4CAF50',
    'error': '#F44336'
}

# Configure styles
def configure_styles():
    style = ttk.Style()
    style.theme_use('clam')
    
    # Main frame style
    style.configure('TFrame', background=COLORS['background'])
    
    # Label styles
    style.configure('TLabel', 
                   background=COLORS['background'], 
                   foreground=COLORS['text'],
                   font=('Segoe UI', 10))
    
    style.configure('Header.TLabel', 
                   font=('Segoe UI', 12, 'bold'),
                   foreground=COLORS['accent'])
    
    # Entry styles
    style.configure('TEntry', 
                   fieldbackground=COLORS['entry_bg'],
                   foreground=COLORS['entry_fg'],
                   insertcolor=COLORS['text'],
                   borderwidth=1,
                   relief='solid')
    
    # Button styles
    style.configure('TButton',
                   background=COLORS['secondary'],
                   foreground=COLORS['text'],
                   borderwidth=1,
                   font=('Segoe UI', 9))
    
    style.configure('Accent.TButton',
                   background=COLORS['accent'],
                   foreground=COLORS['text'],
                   font=('Segoe UI', 9, 'bold'))
    
    style.map('TButton',
              background=[('active', COLORS['button_active'])],
              foreground=[('active', COLORS['text'])])
    
    # Notebook style
    style.configure('TNotebook', background=COLORS['background'])
    style.configure('TNotebook.Tab', 
                   background=COLORS['secondary'],
                   foreground=COLORS['text'],
                   padding=[10, 5],
                   font=('Segoe UI', 10, 'bold'))
    style.map('TNotebook.Tab',
              background=[('selected', COLORS['accent'])],
              foreground=[('selected', COLORS['text'])])
    
    # LabelFrame style
    style.configure('TLabelframe',
                   background=COLORS['background'],
                   foreground=COLORS['accent'])
    style.configure('TLabelframe.Label',
                   background=COLORS['background'],
                   foreground=COLORS['accent'])

# Main application window
root = tk.Tk()
root.title("Cryptography Toolbox")
root.geometry("900x700")
root.configure(bg=COLORS['background'])

# Configure styles
configure_styles()

# Custom fonts
title_font = Font(family='Segoe UI', size=14, weight='bold')
section_font = Font(family='Segoe UI', size=11, weight='bold')

# Notebook widget for tabs
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both', padx=10, pady=10)

# ===== Playfair Tab =====
playfair_tab = ttk.Frame(notebook)
playfair_frame = ttk.LabelFrame(playfair_tab, text=" Playfair Cipher ", padding=15)
playfair_frame.pack(expand=True, fill='both', padx=10, pady=10)

# Configuration
ttk.Label(playfair_frame, text="Configuration:", font=section_font).grid(row=0, column=0, padx=5, pady=5, sticky='w')
playfair_config_var = tk.StringVar(value="Default")

def update_playfair_config(*args):
    global playfair_config
    selected_config = playfair_config_var.get()
    if selected_config == "Default":
        playfair_config = DefaultPlayfairConfig()
    elif selected_config == "Use Null":
        playfair_config = UseNullPlayfairConfig()
    elif selected_config == "No Null":
        playfair_config = NoNullPlayfairConfig()

playfair_config = DefaultPlayfairConfig()
playfair_config_var.trace("w", update_playfair_config)

playfair_config_dropdown = ttk.Combobox(playfair_frame, textvariable=playfair_config_var, 
                                        values=["Default", "Use Null", "No Null"], 
                                        state="readonly")
playfair_config_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# Key input
ttk.Label(playfair_frame, text="Key:", font=section_font).grid(row=1, column=0, padx=5, pady=5, sticky='w')
playfair_key_entry = ttk.Entry(playfair_frame, width=50)
playfair_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

# Input text
ttk.Label(playfair_frame, text="Input Text:", font=section_font).grid(row=2, column=0, padx=5, pady=5, sticky='w')
playfair_input_entry = tk.Text(playfair_frame, width=50, height=5, 
                              bg=COLORS['entry_bg'], fg=COLORS['text'],
                              insertbackground=COLORS['text'],
                              wrap=tk.WORD)
playfair_input_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

# Buttons
playfair_button_frame = ttk.Frame(playfair_frame)
playfair_button_frame.grid(row=3, column=0, columnspan=2, pady=10)

def handle_playfair_encrypt():
    key = playfair_key_entry.get()
    plaintext = playfair_input_entry.get("1.0", tk.END).strip()
    
    if not key:
        messagebox.showerror("Error", "Key cannot be empty!", parent=playfair_tab)
        return
    if not plaintext:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=playfair_tab)
        return
    
    try:
        cipher = PlayfairCipher(key, playfair_config)
        encrypted_text = cipher.encrypt(plaintext)
        playfair_result_text.delete("1.0", tk.END)
        playfair_result_text.insert(tk.END, encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=playfair_tab)

def handle_playfair_decrypt():
    key = playfair_key_entry.get()
    ciphertext = playfair_input_entry.get("1.0", tk.END).strip()
    
    if not key:
        messagebox.showerror("Error", "Key cannot be empty!", parent=playfair_tab)
        return
    if not ciphertext:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=playfair_tab)
        return
    
    try:
        cipher = PlayfairCipher(key, playfair_config)
        decrypted_text = cipher.decrypt(ciphertext)
        playfair_result_text.delete("1.0", tk.END)
        playfair_result_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=playfair_tab)

def clear_playfair_inputs():
    playfair_key_entry.delete(0, tk.END)
    playfair_input_entry.delete("1.0", tk.END)
    playfair_result_text.delete("1.0", tk.END)
    playfair_config_var.set("Default")

playfair_encrypt_button = ttk.Button(playfair_button_frame, text="Encrypt", command=handle_playfair_encrypt, style='Accent.TButton')
playfair_encrypt_button.pack(side='left', padx=5)

playfair_decrypt_button = ttk.Button(playfair_button_frame, text="Decrypt", command=handle_playfair_decrypt, style='Accent.TButton')
playfair_decrypt_button.pack(side='left', padx=5)

playfair_clear_button = ttk.Button(playfair_button_frame, text="Clear All", command=clear_playfair_inputs)
playfair_clear_button.pack(side='left', padx=5)

# Result
ttk.Label(playfair_frame, text="Result:", font=section_font).grid(row=4, column=0, padx=5, pady=5, sticky='nw')
playfair_result_text = tk.Text(playfair_frame, width=50, height=8, 
                              bg=COLORS['entry_bg'], fg=COLORS['text'],
                              insertbackground=COLORS['text'],
                              wrap=tk.WORD)
playfair_result_text.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

# Copy button
def copy_playfair_result():
    result = playfair_result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!", parent=playfair_tab)
    else:
        messagebox.showwarning("Empty", "No result to copy", parent=playfair_tab)

copy_playfair_button = ttk.Button(playfair_frame, text="Copy Result", command=copy_playfair_result)
copy_playfair_button.grid(row=5, column=1, pady=5, sticky='e')

# ===== Polybius Square Tab =====
polybius_tab = ttk.Frame(notebook)
polybius_frame = ttk.LabelFrame(polybius_tab, text=" Polybius Square Cipher ", padding=15)
polybius_frame.pack(expand=True, fill='both', padx=10, pady=10)

# Configuration
ttk.Label(polybius_frame, text="Configuration:", font=section_font).grid(row=0, column=0, padx=5, pady=5, sticky='w')
polybius_config_var = tk.StringVar(value="Default")

def update_polybius_config(*args):
    global polybius_config
    selected_config = polybius_config_var.get()
    if selected_config == "Default":
        polybius_config = DefaultPolybiusSquareConfig()
    elif selected_config == "Use Null":
        polybius_config = UseNullPolybiusSquareConfig()
    elif selected_config == "No Null":
        polybius_config = NoNullPolybiusSquareConfig()

polybius_config = DefaultPolybiusSquareConfig()
polybius_config_var.trace("w", update_polybius_config)

polybius_config_dropdown = ttk.Combobox(polybius_frame, textvariable=polybius_config_var, 
                                      values=["Default", "Use Null", "No Null"], 
                                      state="readonly")
polybius_config_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# Key input
ttk.Label(polybius_frame, text="Key:", font=section_font).grid(row=1, column=0, padx=5, pady=5, sticky='w')
polybius_key_entry = ttk.Entry(polybius_frame, width=50)
polybius_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

# Input text
ttk.Label(polybius_frame, text="Input Text:", font=section_font).grid(row=2, column=0, padx=5, pady=5, sticky='w')
polybius_input_entry = tk.Text(polybius_frame, width=50, height=5, 
                              bg=COLORS['entry_bg'], fg=COLORS['text'],
                              insertbackground=COLORS['text'],
                              wrap=tk.WORD)
polybius_input_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

# Buttons
polybius_button_frame = ttk.Frame(polybius_frame)
polybius_button_frame.grid(row=3, column=0, columnspan=2, pady=10)

def handle_polybius_encrypt():
    key = polybius_key_entry.get()
    plaintext = polybius_input_entry.get("1.0", tk.END).strip()
    
    if not key:
        messagebox.showerror("Error", "Key cannot be empty!", parent=polybius_tab)
        return
    if not plaintext:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=polybius_tab)
        return
    
    try:
        cipher = PolybiusSquareCipher(key, polybius_config)
        encrypted_text = cipher.encrypt(plaintext)
        polybius_result_text.delete("1.0", tk.END)
        polybius_result_text.insert(tk.END, encrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=polybius_tab)

def handle_polybius_decrypt():
    key = polybius_key_entry.get()
    ciphertext = polybius_input_entry.get("1.0", tk.END).strip()
    
    if not key:
        messagebox.showerror("Error", "Key cannot be empty!", parent=polybius_tab)
        return
    if not ciphertext:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=polybius_tab)
        return
    
    try:
        cipher = PolybiusSquareCipher(key, polybius_config)
        decrypted_text = cipher.decrypt(ciphertext)
        polybius_result_text.delete("1.0", tk.END)
        polybius_result_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=polybius_tab)

def clear_polybius_inputs():
    polybius_key_entry.delete(0, tk.END)
    polybius_input_entry.delete("1.0", tk.END)
    polybius_result_text.delete("1.0", tk.END)
    polybius_config_var.set("Default")

polybius_encrypt_button = ttk.Button(polybius_button_frame, text="Encrypt", command=handle_polybius_encrypt, style='Accent.TButton')
polybius_encrypt_button.pack(side='left', padx=5)

polybius_decrypt_button = ttk.Button(polybius_button_frame, text="Decrypt", command=handle_polybius_decrypt, style='Accent.TButton')
polybius_decrypt_button.pack(side='left', padx=5)

polybius_clear_button = ttk.Button(polybius_button_frame, text="Clear All", command=clear_polybius_inputs)
polybius_clear_button.pack(side='left', padx=5)

# Result
ttk.Label(polybius_frame, text="Result:", font=section_font).grid(row=4, column=0, padx=5, pady=5, sticky='nw')
polybius_result_text = tk.Text(polybius_frame, width=50, height=8, 
                              bg=COLORS['entry_bg'], fg=COLORS['text'],
                              insertbackground=COLORS['text'],
                              wrap=tk.WORD)
polybius_result_text.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

# Copy button
def copy_polybius_result():
    result = polybius_result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!", parent=polybius_tab)
    else:
        messagebox.showwarning("Empty", "No result to copy", parent=polybius_tab)

copy_polybius_button = ttk.Button(polybius_frame, text="Copy Result", command=copy_polybius_result)
copy_polybius_button.grid(row=5, column=1, pady=5, sticky='e')

# ===== RSA Tab =====
rsa_tab = ttk.Frame(notebook)
rsa_frame = ttk.LabelFrame(rsa_tab, text=" RSA Encryption ", padding=15)
rsa_frame.pack(expand=True, fill='both', padx=10, pady=10)

# Key management
key_management_frame = ttk.LabelFrame(rsa_frame, text=" Key Management ", padding=10)
key_management_frame.pack(fill='x', padx=5, pady=5)

# Public Key
ttk.Label(key_management_frame, text="Public Key (n,e):").grid(row=0, column=0, padx=5, pady=2, sticky='w')
rsa_public_key_entry = ttk.Entry(key_management_frame, width=70)
rsa_public_key_entry.grid(row=0, column=1, padx=5, pady=2, sticky='ew')

# Private Key
ttk.Label(key_management_frame, text="Private Key (n,d):").grid(row=1, column=0, padx=5, pady=2, sticky='w')
rsa_private_key_entry = ttk.Entry(key_management_frame, width=70)
rsa_private_key_entry.grid(row=1, column=1, padx=5, pady=2, sticky='ew')

# Key buttons
key_button_frame = ttk.Frame(key_management_frame)
key_button_frame.grid(row=2, column=0, columnspan=2, pady=5)

def generate_rsa_keys():
    try:
        rsa = RSA_Cipher(key_size=2048)
        rsa_public_key_entry.delete(0, tk.END)
        rsa_public_key_entry.insert(0, rsa.public_key)
        rsa_private_key_entry.delete(0, tk.END)
        rsa_private_key_entry.insert(0, rsa.private_key)
        
        n, e = rsa._parse_key(rsa.public_key)
        messagebox.showinfo(
            "Keys Generated", 
            f"RSA-{n.bit_length()} keys generated:\n\n"
            f"Public: (n={str(n)[:20]}..., e={e})\n"
            f"Private: (n={str(n)[:20]}..., d=...)",
            parent=rsa_tab
        )
    except Exception as e:
        messagebox.showerror("Key Generation Failed", str(e), parent=rsa_tab)

def verify_rsa_keys():
    public_key = rsa_public_key_entry.get()
    private_key = rsa_private_key_entry.get()
    
    if not public_key and not private_key:
        messagebox.showinfo("No Keys", "Please enter keys to verify", parent=rsa_tab)
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
        
        messagebox.showinfo("Key Verification", "\n\n".join(messages), parent=rsa_tab)
    except Exception as e:
        messagebox.showerror("Invalid Key Format", str(e), parent=rsa_tab)

def clear_rsa_keys():
    rsa_public_key_entry.delete(0, tk.END)
    rsa_private_key_entry.delete(0, tk.END)
    messagebox.showinfo("Cleared", "Key fields have been cleared", parent=rsa_tab)

generate_button = ttk.Button(key_button_frame, text="Generate Keys", command=generate_rsa_keys, style='Accent.TButton')
generate_button.pack(side='left', padx=5)

verify_button = ttk.Button(key_button_frame, text="Verify Keys", command=verify_rsa_keys)
verify_button.pack(side='left', padx=5)

clear_button = ttk.Button(key_button_frame, text="Clear Keys", command=clear_rsa_keys)
clear_button.pack(side='left', padx=5)

# Input/Output
io_frame = ttk.LabelFrame(rsa_frame, text=" Encryption/Decryption ", padding=10)
io_frame.pack(fill='both', expand=True, padx=5, pady=5)

# Input
ttk.Label(io_frame, text="Input Text:", font=section_font).grid(row=0, column=0, padx=5, pady=5, sticky='w')
rsa_input_entry = tk.Text(io_frame, width=70, height=5, 
                         bg=COLORS['entry_bg'], fg=COLORS['text'],
                         insertbackground=COLORS['text'],
                         wrap=tk.WORD)
rsa_input_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# Buttons
rsa_button_frame = ttk.Frame(io_frame)
rsa_button_frame.grid(row=1, column=0, columnspan=2, pady=10)

def handle_rsa_encrypt():
    public_key = rsa_public_key_entry.get()
    plaintext = rsa_input_entry.get("1.0", tk.END).strip()
    
    if not public_key:
        messagebox.showerror("Error", "Public key is required for encryption!", parent=rsa_tab)
        return
    if not plaintext:
        messagebox.showerror("Error", "Plaintext cannot be empty!", parent=rsa_tab)
        return
    
    try:
        rsa = RSA_Cipher(public_key=public_key)
        ciphertext = rsa.encrypt(plaintext)
        rsa_result_text.delete("1.0", tk.END)
        rsa_result_text.insert(tk.END, ciphertext)
    except Exception as e:
        messagebox.showerror("Encryption Failed", str(e), parent=rsa_tab)

def handle_rsa_decrypt():
    private_key = rsa_private_key_entry.get()
    ciphertext = rsa_input_entry.get("1.0", tk.END).strip()
    
    if not private_key:
        messagebox.showerror("Error", "Private key is required for decryption!", parent=rsa_tab)
        return
    if not ciphertext:
        messagebox.showerror("Error", "Ciphertext cannot be empty!", parent=rsa_tab)
        return
    
    try:
        rsa = RSA_Cipher(private_key=private_key)
        plaintext = rsa.decrypt(ciphertext)
        rsa_result_text.delete("1.0", tk.END)
        rsa_result_text.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e), parent=rsa_tab)

def clear_rsa_input():
    rsa_input_entry.delete("1.0", tk.END)
    rsa_result_text.delete("1.0", tk.END)

rsa_encrypt_button = ttk.Button(rsa_button_frame, text="Encrypt", command=handle_rsa_encrypt, style='Accent.TButton')
rsa_encrypt_button.pack(side='left', padx=5)

rsa_decrypt_button = ttk.Button(rsa_button_frame, text="Decrypt", command=handle_rsa_decrypt, style='Accent.TButton')
rsa_decrypt_button.pack(side='left', padx=5)

clear_input_button = ttk.Button(rsa_button_frame, text="Clear Input", command=clear_rsa_input)
clear_input_button.pack(side='left', padx=5)

# Result
ttk.Label(io_frame, text="Result:", font=section_font).grid(row=2, column=0, padx=5, pady=5, sticky='nw')
rsa_result_text = tk.Text(io_frame, width=70, height=8, 
                         bg=COLORS['entry_bg'], fg=COLORS['text'],
                         insertbackground=COLORS['text'],
                         wrap=tk.WORD)
rsa_result_text.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

# Copy button
def copy_rsa_result():
    result = rsa_result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!", parent=rsa_tab)
    else:
        messagebox.showwarning("Empty", "No result to copy", parent=rsa_tab)

copy_rsa_button = ttk.Button(io_frame, text="Copy Result", command=copy_rsa_result)
copy_rsa_button.grid(row=3, column=1, pady=5, sticky='e')

# UI State Management
def update_rsa_buttons():
    public_key = rsa_public_key_entry.get().strip()
    private_key = rsa_private_key_entry.get().strip()
    input_text = rsa_input_entry.get("1.0", tk.END).strip()
    
    rsa_encrypt_button.config(state=tk.NORMAL if (public_key and input_text) else tk.DISABLED)
    rsa_decrypt_button.config(state=tk.NORMAL if (private_key and input_text) else tk.DISABLED)

rsa_public_key_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())
rsa_private_key_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())
rsa_input_entry.bind("<KeyRelease>", lambda e: update_rsa_buttons())

# Initialize button states
update_rsa_buttons()

# ===== Steganography Tab =====
steg_tab = ttk.Frame(notebook)
steg_frame = ttk.LabelFrame(steg_tab, text=" Image Steganography ", padding=15)
steg_frame.pack(expand=True, fill='both', padx=10, pady=10)

# Data to encode
ttk.Label(steg_frame, text="Data to Encode:", font=section_font).grid(row=0, column=0, padx=5, pady=5, sticky='w')
steg_data_entry = tk.Text(steg_frame, width=70, height=5, 
                         bg=COLORS['entry_bg'], fg=COLORS['text'],
                         insertbackground=COLORS['text'],
                         wrap=tk.WORD)
steg_data_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# File path
ttk.Label(steg_frame, text="Image File:", font=section_font).grid(row=1, column=0, padx=5, pady=5, sticky='w')
steg_file_entry = ttk.Entry(steg_frame, width=70)
steg_file_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

def browse_image_file():
    filename = filedialog.askopenfilename(
        title="Select Image File",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp"), ("All Files", "*.*")]
    )
    if filename:
        steg_file_entry.delete(0, tk.END)
        steg_file_entry.insert(0, filename)

browse_file_button = ttk.Button(steg_frame, text="Browse", command=browse_image_file)
browse_file_button.grid(row=1, column=2, padx=5, pady=5)

# Output path
ttk.Label(steg_frame, text="Output File:", font=section_font).grid(row=2, column=0, padx=5, pady=5, sticky='w')
steg_output_entry = ttk.Entry(steg_frame, width=70)
steg_output_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

def browse_output_file():
    filename = filedialog.asksaveasfilename(
        title="Save Output File",
        defaultextension=".png",
        filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")]
    )
    if filename:
        steg_output_entry.delete(0, tk.END)
        steg_output_entry.insert(0, filename)

browse_output_button = ttk.Button(steg_frame, text="Browse", command=browse_output_file)
browse_output_button.grid(row=2, column=2, padx=5, pady=5)

# Buttons
steg_button_frame = ttk.Frame(steg_frame)
steg_button_frame.grid(row=3, column=0, columnspan=3, pady=10)

def handle_encode():
    data = steg_data_entry.get("1.0", tk.END).strip()
    file_path = steg_file_entry.get()
    output_path = steg_output_entry.get()
    
    if not data:
        messagebox.showerror("Error", "Data to encode cannot be empty!", parent=steg_tab)
        return
    if not file_path:
        messagebox.showerror("Error", "Image file path cannot be empty!", parent=steg_tab)
        return
    if not output_path:
        messagebox.showerror("Error", "Output file path cannot be empty!", parent=steg_tab)
        return
    
    try:
        steganography = SteganographyLSBImage()
        steganography.encode(data, file_path, output_path)
        messagebox.showinfo("Success", "Data encoded successfully!", parent=steg_tab)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=steg_tab)

def handle_decode():
    file_path = steg_file_entry.get()
    output_path = steg_output_entry.get()
    
    if not file_path:
        messagebox.showerror("Error", "Image file path cannot be empty!", parent=steg_tab)
        return
    
    try:
        steganography = SteganographyLSBImage()
        decoded_data = steganography.decode(file_path, output_path=output_path if output_path else None)
        steg_result_text.delete("1.0", tk.END)
        steg_result_text.insert(tk.END, decoded_data)
        messagebox.showinfo("Success", "Data decoded successfully!", parent=steg_tab)
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=steg_tab)

steg_encode_button = ttk.Button(steg_button_frame, text="Encode", command=handle_encode, style='Accent.TButton')
steg_encode_button.pack(side='left', padx=5)

steg_decode_button = ttk.Button(steg_button_frame, text="Decode", command=handle_decode, style='Accent.TButton')
steg_decode_button.pack(side='left', padx=5)

# Result
ttk.Label(steg_frame, text="Decoded Result:", font=section_font).grid(row=4, column=0, padx=5, pady=5, sticky='nw')
steg_result_text = tk.Text(steg_frame, width=70, height=8, 
                          bg=COLORS['entry_bg'], fg=COLORS['text'],
                          insertbackground=COLORS['text'],
                          wrap=tk.WORD)
steg_result_text.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

# Copy button
def copy_steg_result():
    result = steg_result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!", parent=steg_tab)
    else:
        messagebox.showwarning("Empty", "No result to copy", parent=steg_tab)

copy_steg_button = ttk.Button(steg_frame, text="Copy Result", command=copy_steg_result)
copy_steg_button.grid(row=5, column=1, pady=5, sticky='e')

# ===== EAS Tab (Placeholder) =====
eas_tab = ttk.Frame(notebook)

eas_frame = ttk.LabelFrame(eas_tab, text=" AES Encryption ", padding=15)
eas_frame.pack(expand=True, fill='both', padx=10, pady=10)

# Key input
ttk.Label(eas_frame, text="Key (16/24/32 chars):", font=section_font).grid(row=0, column=0, padx=5, pady=5, sticky='w')
aes_key_entry = ttk.Entry(eas_frame, width=50)
aes_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

# IV input
ttk.Label(eas_frame, text="IV (16 bytes, optional):", font=section_font).grid(row=1, column=0, padx=5, pady=5, sticky='w')
aes_iv_entry = ttk.Entry(eas_frame, width=50)
aes_iv_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

# Input text
ttk.Label(eas_frame, text="Input Text:", font=section_font).grid(row=2, column=0, padx=5, pady=5, sticky='w')
aes_input_entry = tk.Text(eas_frame, width=50, height=5, 
                          bg=COLORS['entry_bg'], fg=COLORS['text'],
                          insertbackground=COLORS['text'],
                          wrap=tk.WORD)
aes_input_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

# Buttons
aes_button_frame = ttk.Frame(eas_frame)
aes_button_frame.grid(row=3, column=0, columnspan=2, pady=10)

def handle_aes_encrypt():
    key = aes_key_entry.get().encode('utf-8')
    iv = aes_iv_entry.get().encode('utf-8') if aes_iv_entry.get() else generate_iv()
    plaintext = aes_input_entry.get("1.0", tk.END).strip().encode('utf-8')
    
    if len(key) not in (16, 24, 32):
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters!", parent=eas_tab)
        return
    if not plaintext:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=eas_tab)
        return
    
    try:
        aes = AES(key)
        ciphertext = aes.encrypt_cbc(plaintext, iv)
        hmac = aes.hmac_sha256(key, ciphertext)
        full_output = iv + hmac + ciphertext
        aes_result_text.delete("1.0", tk.END)
        aes_result_text.insert(tk.END, custom_b64encode(full_output))
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=eas_tab)

def handle_aes_decrypt():
    key = aes_key_entry.get().encode('utf-8')
    full_input = custom_b64decode(aes_input_entry.get("1.0", tk.END).strip())
    
    if len(key) not in (16, 24, 32):
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters!", parent=eas_tab)
        return
    if not full_input:
        messagebox.showerror("Error", "Input text cannot be empty!", parent=eas_tab)
        return
    
    try:
        iv = full_input[:16]
        hmac = full_input[16:48]
        ciphertext = full_input[48:]
        
        aes = AES(key)
        expected_hmac = aes.hmac_sha256(key, ciphertext)
        if hmac != expected_hmac:
            messagebox.showerror("Error", "HMAC verification failed! Message may be corrupted.", parent=eas_tab)
            return
        
        plaintext = aes.decrypt_cbc(ciphertext, iv)
        aes_result_text.delete("1.0", tk.END)
        aes_result_text.insert(tk.END, plaintext.decode('utf-8'))
    except Exception as e:
        messagebox.showerror("Error", str(e), parent=eas_tab)

def clear_aes_inputs():
    aes_key_entry.delete(0, tk.END)
    aes_iv_entry.delete(0, tk.END)
    aes_input_entry.delete("1.0", tk.END)
    aes_result_text.delete("1.0", tk.END)

aes_encrypt_button = ttk.Button(aes_button_frame, text="Encrypt", command=handle_aes_encrypt, style='Accent.TButton')
aes_encrypt_button.pack(side='left', padx=5)

aes_decrypt_button = ttk.Button(aes_button_frame, text="Decrypt", command=handle_aes_decrypt, style='Accent.TButton')
aes_decrypt_button.pack(side='left', padx=5)

aes_clear_button = ttk.Button(aes_button_frame, text="Clear All", command=clear_aes_inputs)
aes_clear_button.pack(side='left', padx=5)

# Result
ttk.Label(eas_frame, text="Result:", font=section_font).grid(row=4, column=0, padx=5, pady=5, sticky='nw')
aes_result_text = tk.Text(eas_frame, width=50, height=8, 
                          bg=COLORS['entry_bg'], fg=COLORS['text'],
                          insertbackground=COLORS['text'],
                          wrap=tk.WORD)
aes_result_text.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

# Copy button
def copy_aes_result():
    result = aes_result_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!", parent=eas_tab)
    else:
        messagebox.showwarning("Empty", "No result to copy", parent=eas_tab)

copy_aes_button = ttk.Button(eas_frame, text="Copy Result", command=copy_aes_result)
copy_aes_button.grid(row=5, column=1, pady=5, sticky='e')

# Add all tabs
notebook.add(playfair_tab, text="Playfair")
notebook.add(polybius_tab, text="Polybius")
notebook.add(rsa_tab, text="RSA")
notebook.add(eas_tab, text="EAS")
notebook.add(steg_tab, text="Steganography")


# Run the application
root.mainloop()