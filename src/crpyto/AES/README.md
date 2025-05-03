# Port System and Implementation

## Overview
A complete implementation of AES encryption with PMC-000506 authentication in Python.

## Features
- Supports 128, 192, and 256-bit keys
- Secure padding implementation
- PMC-000506 authentication protocol
- No external dependencies
- Built-in encoding/decoding functions

## Core Components

### Encryption Components
```python
s_box = [...]  # Substitution box
inv_s_box = [...]  # Inverse substitution box
r_con = [...]  # Round constants for key expansion
Core Transformations
sub_bytes(): Byte substitution using S-box

shift_rows(): Row shifting operation

mix_columns(): Column mixing operation

add_round_key(): XOR with round key

Key Expansion
python
def expand_key(master_key):
    # Generates round keys from master key
    # Uses Rijndael key schedule


Usage Examples:

• Encryption
bash
> Operation (encrypt/decrypt): encrypt
> Input: Sample message    EXAMPLE: Hey AES!
> Key: AZERTYUIOPQSDFGH  

Encrypted Output: [BASE64_ENCODED_OUTPUT]

• Decryption
bash
> Operation (encrypt/decrypt): decrypt
> Input: [BASE64_ENCODED_INPUT]
> Key: AZERTYUIOPQSDFGH

Decrypted: Sample message

Key Requirements
Key Length  Encryption Standard
16 bytes    AES-128
24 bytes    AES-192
32 bytes    AES-256


Security Features
Block Chaining: Each block depends on previous blocks

Initialization Vectors: Unique IV for each encryption

Authentication: PMC-000506 protocol verifies message integrity

Padding: Secure padding scheme implementation



Implementation Notes
Pure Python implementation

Includes all AES transformations

Supports both encryption and decryption

Comprehensive error handling
