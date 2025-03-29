# Cryptography Project  

## Guidelines  

Hey there! Welcome to the cryptography project. Let’s stay organized by following these easy guidelines:  

### Branching  
- **No pushing to main directly:**  
  Always create a separate branch for your work using the format `feature/<feature-name>`. For example, if you’re working on the Playfair cipher, name your branch `feature/crypt-playfair`.  

### Code Conventions  
- **Inheritance:**  
  - When creating a new cipher, make sure it inherits from either `AsymetricCrypto` or `SymetricCrypto`.  

- **File Organization:**  
  - Place all cipher-related Python files in the `src/crypto` folder.  

### Formatting & Linting  
To keep things clean and consistent (like in `playfair_cipher.py`), use `ruff` for automatic formatting and linting.  

#### How to Use `ruff`:  
1. **Install it:**  
   ```bash  
   pip install ruff  
   ```  
2. **Format your file:**  
   ```bash  
   ruff format --fix filename.py  
   ```  


---

## To-Do List  

### A. Classical Cryptography  
1. **Substitution Ciphers**  
   - [ ] Vigenère Cipher (optional)  
   - [x] Playfair Cipher  

2. **Transposition (Permutation) Ciphers**  
   - [ ] Complex Columnar Transposition  (optional)  
   - [x] Polybius Square Transposition  

### B. Modern Cryptography  
1. **Secret Key Encryption**  
   - [ ] DES (Data Encryption Standard)  (optional)  
   - [ ] AES (Advanced Encryption Standard)  

2. **Public Key Encryption**  
   - [x] RSA (Rivest-Shamir-Adleman)  
   - [ ] Diffie-Hellman (Key Exchange)  (optional)  
   - [ ] Hashing Algorithms (e.g., SHA-256, MD5)  (optional) 

