# Cryptography Project – Report

## Project Setup

### Installation

* **Clone via Git:**

  ```bash
  git clone https://github.com/B-AJ-Amar/cryptography-project.git
  ```

* **Or download the `.zip` file:**

  ![Download ZIP](./img/image.png)

### Run the GUI

```bash
cd src
python main.py
```

### Run Unit Tests

```bash
cd src
pytest
```

---

## Architecture Overview

### Base Cryptographic Classes (`base.py`)

Defines a unified structure for cryptographic implementations:

* **`Crypto` (Abstract Base Class):**

  * Defines `encrypt()` and `decrypt()` as required methods.
  * Enforced via Python’s `ABC` module.

* **`SymmetricCrypto`:**

  * For classical ciphers like Playfair and Polybius.
  * Includes built-in key handling (`get_key()`, `set_key()`).

* **`AsymmetricCrypto`:**

  * For key-pair systems like RSA.
  * Automatically generates keys when not provided.

---

## Playfair Cipher

**Files**: `playfair_cipher.py`, `playfair_conf.py`

### Features

* **Three Modes**:

  1. `Classic`: 5×5 grid (I/J merged) — historical accuracy.
  2. `UseNull`: 16×12 grid — full ASCII with NULL-byte padding.
  3. `NoNull`: 19×10 grid — printable ASCII only.

* **Separation of Concerns**:

  * `playfair_conf.py`: Defines character sets, padding rules, and grid logic.
  * `playfair_cipher.py`: Executes encryption/decryption.

### Security & Design

* Padding: Automatic (NULL/²) for odd-length inputs.
* Deduplication: Customizable character substitution.
* Grid logic prevents edge-wrapping and maintains key order.

### Benefits

* Historical compatibility (Classic).
* Binary & text data support (UseNull, NoNull).
* Easy mode updates via configuration changes.

---

## Polybius Square Cipher

**Files**: `polybius_square_cipher.py`, `polybius_square_conf.py`

### Features

* **Three Modes**:

  1. `Classic`: 5×5 grid (I/J merged).
  2. `UseNull`: 16×12 grid for full ASCII (incl. control chars).
  3. `NoNull`: 19×10 grid — printable ASCII only.

* **Config-Driven Design**:

  * `polybius_square_conf.py`: Character sets and grid layout.
  * `polybius_square_cipher.py`: Encodes/decodes via coordinates.

### Security & Design

* Grid is key-first, then auto-filled.
* Classic filters non-alphabetic characters.
* Extended modes support case, special characters, and missing data handling.

### Benefits

* Historical fidelity.
* Modern data (text, binary) compatibility.
* Config-only updates for new modes.

---

## RSA Public-Key Cipher

**File**: `rsa_cipher.py`

### Features

* 2048-bit minimum key size.
* UTF-8 support.
* Automatic key generation.

### Key Innovations

1. **Message Chunking**:

   * Auto-calculates max chunk size with `_calculate_max_chunk_size()`.
   * Prevents overflow of modulus size.

2. **Prime Generation**:

   * Small prime pre-check + Miller-Rabin (5 iterations).
   * High accuracy and performance.

3. **Key Validation**:

   * Ensures: `n ≥ 2048 bits`, `e = 65537`, and valid modular inverse for `d`.

### Security Decisions

| Choice             | Reason                        | Implemented In   |
| ------------------ | ----------------------------- | ---------------- |
| `e = 65537`        | Security/performance tradeoff | `generate_key()` |
| Miller-Rabin `k=5` | Probabilistic prime checking  | `_is_prime()`    |

### Implementation Notes

* Key format: `n,e` or `n,d` (comma-separated integers).
* Message flow: UTF-8 → bytes → int chunks → RSA.
* Errors: Handles key format and message size issues gracefully.

---

## Steganography System

**File**: `image.py`

### LSB Encoding Process

* **Embedding**:

  * Message → binary → appended 17-bit terminator (`1 + 16×0`).
  * For each pixel: LSBs of R/G/B are set to message bits.

* **Capacity**:

  * 1 pixel = 3 bits (RGB).
  * Works best with 24-bit PNG images.

### Detection Resistance

| Aspect      | Comment                               |
| ----------- | ------------------------------------- |
| Visual      | No noticeable quality loss            |
| Statistical | Vulnerable without masking/encryption |

---

## Encryption vs. Steganography

| Aspect        | Encryption                                    | Steganography                                |
| ------------- | --------------------------------------------- | -------------------------------------------- |
| Purpose       | Confidentiality via scrambling (requires key) | Concealment via embedding                    |
| Output        | Ciphertext (unreadable)                       | Innocent-looking medium (e.g., image, audio) |
| Reversibility | Reversible with key                           | Not reversible (focus on hidden presence)    |
| Use Cases     | Secure channels (SSL, VPN)                    | Covert messaging, digital watermarking       |

---

## Screenshots

![screenshot 1](./img/s1.png)
![screenshot 2](./img/s2.png)
![screenshot 5](./img/s5.png)


