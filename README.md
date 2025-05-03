# Report : Cryptography Project  



## **0. project setup**

- **1. installation :**
  - using git clone :
  ```bash
  git clone https://github.com/B-AJ-Amar/cryptography-project.git
  ```
  - or download `.zip` file :
  - 
  ![alt text](./img/image.png)

- **2. run the gui :**
  ```bash
  cd src
  python main.py
  ```

 - **2. Unit Tests:**
   ```bash
   cd src
   pytest
   ```

## **1. Foundation Architecture**

### **Base Cryptographic Classes (`base.py`)**

**Purpose**: Provides the structural backbone for all cryptographic implementations.

**Key Components**:

- **`Crypto` (Abstract Base Class)**
    - *What*: Defines the mandatory interface (**`encrypt()`**, **`decrypt()`**)
    - *Why*: Ensures all ciphers have consistent functionality
    - *How*: Uses Python's **`ABC`** module to enforce method implementation
- **`SymmetricCrypto`**
    - Handles single-key algorithms (Playfair, Polybius)
    - Simplifies development of classical ciphers
    - *Key Feature*: Built-in key management (**`get_key()`**, **`set_key()`**)
- **`AsymmetricCrypto`**
    - Manages public/private key pairs (RSA)
    - Automates key generation if none provided


### **Playfair Cipher System**

*(playfair_cipher.py + playfair_conf.py)*

**Core Functionality**

**Key Innovations**

1. **Three Specialized Modes**
    - *Classic*: 5×5 grid (A-Z, J→I) for historical accuracy
    - *UseNull*: Full ASCII support (16×12 grid) with NULL-byte padding
    - *NoNull*: Printable ASCII only (19×10 grid) for text processing
2. **Adaptive Architecture**
    - *playfair_conf.py*: Centralizes all cryptographic rules (character sets, grid math, padding)
    - *playfair_cipher.py*: Pure execution engine applying config-defined transformations

**Security & Design**

- **Character Handling**:
    - Classic mode merges I/J for 25-letter grid
    - Extended modes use optimized grids (192 chars for full ASCII coverage)
- **Data Processing**:
    - Automatic padding (NULL/²) for odd-length input
    - Deduplication with configurable substitution
- **Grid Optimization**:
    - Prevents edge-wrapping collisions
    - Maintains key order integrity
    - 
**Implementation Benefits**

1. Classic mode matches original WWI specifications
2. Handles both text (NoNull) and binary data (UseNull)
3. New modes require only config updates 


### **Polybius Square Cipher System**

*(polybius_square_cipher.py + polybius_square_conf.py)*

**Core Functionality**

**Key Innovations**

1. **Three Specialized Modes**
    - *Classic*: 5×5 grid (A-Z, I/J merged) for historical accuracy
    - *UseNull*: Full ASCII support (16×12 grid) including control characters
    - *NoNull*: Printable ASCII only (19×10 grid) for clean text processing
2. **Adaptive Architecture**
    - *polybius_square_conf.py*: Centralizes all grid configurations and character handling
    - *polybius_square_cipher.py*: Pure coordinate transformation engine

**Security & Design**

- **Grid Generation**:
    - Keys populate grid first (duplicates removed)
    - Remaining slots filled systematically
    - Dynamic sizing (5×5 to 19×10) based on character set
- **Data Handling**:
    - Classic mode filters non-alphabetic characters
    - Extended modes preserve case and special characters
    - Graceful handling of missing characters

**Implementation Benefits**

1. Classic mode matches ancient Greek military cipher
2. Supports both modern text and binary data
3. New character sets require only config updates


### **RSA Public-Key Cryptosystem (`rsa_cipher.py`)**

**Core Functionality**

Secure asymmetric encryption for data transmission without pre-shared secrets, featuring:

- **2048-bit minimum key security**
- **UTF-8 message handling**
- **Automatic key generation**

**Key Innovations**

1. **Adaptive Message Chunking**
   - **Problem**: RSA cannot natively encrypt data > modulus size  
   - **Solution**:
     - Calculates maximum chunk size via `_calculate_max_chunk_size()`
     - Splits UTF-8 encoded messages into optimal blocks  
   - **Safety Margin**: ⌊log₂(n)⌋ − 1 bits per chunk

2. **Optimized Prime Generation**
   - **Method**:
     1. Pre-screening with small primes (2–37)
     2. Miller-Rabin test (k = 5 iterations)
   - **Accuracy**: 99.999% confidence per prime  
   - **Performance**: Bitmask ensures odd numbers of correct length

3. **Key Validation**
   - Enforces:
     - Modulus (`n`) ≥ 2048 bits
     - Public exponent (`e`) fixed at 65537
     - Private exponent (`d`) exists via modular inverse

**Security Decisions**

| **Choice**         | **Rationale**                         | **Implementation**         |
|--------------------|----------------------------------------|-----------------------------|
| `e = 65537`        | Balances security and performance     | Hardcoded in `generate_key()` |
| Miller-Rabin `k=5` | Optimal probabilistic primality check | `_is_prime()` method         |


**Implementation Notes**

- **Key Format**: Comma-separated integers (`n,e` or `n,d`)
- **Message Handling**:
  - **Encryption**: UTF-8 → bytes → chunks → big-endian integers
  - **Decryption**: Big-endian integers → bytes → UTF-8 string
- **Error Handling**: Detects invalid key formats and oversized messages

---

##  Encryption vs. Steganography  


| **Aspect**          | **Encryption**                               | **Steganography**                           |
|---------------------|----------------------------------------------|---------------------------------------------|
| **Purpose**         | To scramble data for confidentiality (requires decryption key). | To hide a message inside another medium (e.g., image, audio). |
| **Output**          | Scrambled, unreadable ciphertext             | Innocent-looking medium with hidden data     |
| **Reversibility**   | **Two-way** (reversible with key)            | Not applicable (focus is on concealment)     |
| **Use Cases**       | Secure communication (e.g., SSL, VPN)       | Covert communication, digital watermarking   |








## Screenshots
![alt text](./img/s1.png)
![alt text](./img/s2.png)
![alt text](./img/s5.png)







<br><br><br><br><br><br><br><br><br><br>
<br><br><br><br><br><br><br><br><br><br>

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
  
### C. Steganography  (optional)
For more details , click [here](./src/steganography/README.md).

- [x] image


https://www.notion.so/1e00e4e3e9538078b542d258ca728eb0?pvs=4