import os

s_box = {
    0x00: 0x63, 0x01: 0x7C, 0x02: 0x77, 0x03: 0x7B, 0x04: 0xF2, 0x05: 0x6B, 0x06: 0x6F, 0x07: 0xC5,
    0x08: 0x30, 0x09: 0x01, 0x0A: 0x67, 0x0B: 0x2B, 0x0C: 0xFE, 0x0D: 0xD7, 0x0E: 0xAB, 0x0F: 0x76,
    0x10: 0xCA, 0x11: 0x82, 0x12: 0xC9, 0x13: 0x7D, 0x14: 0xFA, 0x15: 0x59, 0x16: 0x47, 0x17: 0xF0,
    0x18: 0xAD, 0x19: 0xD4, 0x1A: 0xA2, 0x1B: 0xAF, 0x1C: 0x9C, 0x1D: 0xA4, 0x1E: 0x72, 0x1F: 0xC0,
    0x20: 0xB7, 0x21: 0xFD, 0x22: 0x93, 0x23: 0x26, 0x24: 0x36, 0x25: 0x3F, 0x26: 0xF7, 0x27: 0xCC,
    0x28: 0x34, 0x29: 0xA5, 0x2A: 0xE5, 0x2B: 0xF1, 0x2C: 0x71, 0x2D: 0xD8, 0x2E: 0x31, 0x2F: 0x15,
    0x30: 0x04, 0x31: 0xC7, 0x32: 0x23, 0x33: 0xC3, 0x34: 0x18, 0x35: 0x96, 0x36: 0x05, 0x37: 0x9A,
    0x38: 0x07, 0x39: 0x12, 0x3A: 0x80, 0x3B: 0xE2, 0x3C: 0xEB, 0x3D: 0x27, 0x3E: 0xB2, 0x3F: 0x75,
    0x40: 0x09, 0x41: 0x83, 0x42: 0x2C, 0x43: 0x1A, 0x44: 0x1B, 0x45: 0x6E, 0x46: 0x5A, 0x47: 0xA0,
    0x48: 0x52, 0x49: 0x3B, 0x4A: 0xD6, 0x4B: 0xB3, 0x4C: 0x29, 0x4D: 0xE3, 0x4E: 0x2F, 0x4F: 0x84,
    0x50: 0x53, 0x51: 0xD1, 0x52: 0x00, 0x53: 0xED, 0x54: 0x20, 0x55: 0xFC, 0x56: 0xB1, 0x57: 0x5B,
    0x58: 0x6A, 0x59: 0xCB, 0x5A: 0xBE, 0x5B: 0x39, 0x5C: 0x4A, 0x5D: 0x4C, 0x5E: 0x58, 0x5F: 0xCF,
    0x60: 0xD0, 0x61: 0xEF, 0x62: 0xAA, 0x63: 0xFB, 0x64: 0x43, 0x65: 0x4D, 0x66: 0x33, 0x67: 0x85,
    0x68: 0x45, 0x69: 0xF9, 0x6A: 0x02, 0x6B: 0x7F, 0x6C: 0x50, 0x6D: 0x3C, 0x6E: 0x9F, 0x6F: 0xA8,
    0x70: 0x51, 0x71: 0xA3, 0x72: 0x40, 0x73: 0x8F, 0x74: 0x92, 0x75: 0x9D, 0x76: 0x38, 0x77: 0xF5,
    0x78: 0xBC, 0x79: 0xB6, 0x7A: 0xDA, 0x7B: 0x21, 0x7C: 0x10, 0x7D: 0xFF, 0x7E: 0xF3, 0x7F: 0xD2,
    0x80: 0xCD, 0x81: 0x0C, 0x82: 0x13, 0x83: 0xEC, 0x84: 0x5F, 0x85: 0x97, 0x86: 0x44, 0x87: 0x17,
    0x88: 0xC4, 0x89: 0xA7, 0x8A: 0x7E, 0x8B: 0x3D, 0x8C: 0x64, 0x8D: 0x5D, 0x8E: 0x19, 0x8F: 0x73,
    0x90: 0x60, 0x91: 0x81, 0x92: 0x4F, 0x93: 0xDC, 0x94: 0x22, 0x95: 0x2A, 0x96: 0x90, 0x97: 0x88,
    0x98: 0x46, 0x99: 0xEE, 0x9A: 0xB8, 0x9B: 0x14, 0x9C: 0xDE, 0x9D: 0x5E, 0x9E: 0x0B, 0x9F: 0xDB,
    0xA0: 0xE0, 0xA1: 0x32, 0xA2: 0x3A, 0xA3: 0x0A, 0xA4: 0x49, 0xA5: 0x06, 0xA6: 0x24, 0xA7: 0x5C,
    0xA8: 0xC2, 0xA9: 0xD3, 0xAA: 0xAC, 0xAB: 0x62, 0xAC: 0x91, 0xAD: 0x95, 0xAE: 0xE4, 0xAF: 0x79,
    0xB0: 0xE7, 0xB1: 0xC8, 0xB2: 0x37, 0xB3: 0x6D, 0xB4: 0x8D, 0xB5: 0xD5, 0xB6: 0x4E, 0xB7: 0xA9,
    0xB8: 0x6C, 0xB9: 0x56, 0xBA: 0xF4, 0xBB: 0xEA, 0xBC: 0x65, 0xBD: 0x7A, 0xBE: 0xAE, 0xBF: 0x08,
    0xC0: 0xBA, 0xC1: 0x78, 0xC2: 0x25, 0xC3: 0x2E, 0xC4: 0x1C, 0xC5: 0xA6, 0xC6: 0xB4, 0xC7: 0xC6,
    0xC8: 0xE8, 0xC9: 0xDD, 0xCA: 0x74, 0xCB: 0x1F, 0xCC: 0x4B, 0xCD: 0xBD, 0xCE: 0x8B, 0xCF: 0x8A,
    0xD0: 0x70, 0xD1: 0x3E, 0xD2: 0xB5, 0xD3: 0x66, 0xD4: 0x48, 0xD5: 0x03, 0xD6: 0xF6, 0xD7: 0x0E,
    0xD8: 0x61, 0xD9: 0x35, 0xDA: 0x57, 0xDB: 0xB9, 0xDC: 0x86, 0xDD: 0xC1, 0xDE: 0x1D, 0xDF: 0x9E,
    0xE0: 0xE1, 0xE1: 0xF8, 0xE2: 0x98, 0xE3: 0x11, 0xE4: 0x69, 0xE5: 0xD9, 0xE6: 0x8E, 0xE7: 0x94,
    0xE8: 0x9B, 0xE9: 0x1E, 0xEA: 0x87, 0xEB: 0xE9, 0xEC: 0xCE, 0xED: 0x55, 0xEE: 0x28, 0xEF: 0xDF,
    0xF0: 0x8C, 0xF1: 0xA1, 0xF2: 0x89, 0xF3: 0x0D, 0xF4: 0xBF, 0xF5: 0xE6, 0xF6: 0x42, 0xF7: 0x68,
    0xF8: 0x41, 0xF9: 0x99, 0xFA: 0x2D, 0xFB: 0x0F, 0xFC: 0xB0, 0xFD: 0x54, 0xFE: 0xBB, 0xFF: 0x16,
}

inv_s_box = {v: k for k, v in s_box.items()}


def bytes_to_matrix(block):
    assert len(block) == 16, "Block must be 16 bytes"
    return [list(block[i::4]) for i in range(4)]


def matrix_to_bytes(matrix):
    return bytes(sum(zip(*matrix), ()))


def add_round_key(state, key):
    return [[s ^ k for s, k in zip(state_row, key_row)] for state_row, key_row in zip(state, key)]


def sub_bytes(state):
    return [[s_box[byte] for byte in row] for row in state]


def inv_sub_bytes(state):
    return [[inv_s_box[byte] for byte in row] for row in state]


def shift_rows(state):
    return [state[i][i:] + state[i][:i] for i in range(4)]


def inv_shift_rows(state):
    return [state[i][-i:] + state[i][:-i] if i != 0 else state[i] for i in range(4)]


def galois_mult(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return result & 0xff


def mixer(matrix, state):
    result = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                result[i][j] ^= galois_mult(matrix[i][k], state[k][j])
    return result


def mix_columns(state):
    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    return mixer(mix_matrix, state)


def inv_mix_columns(state):
    inv_mix_matrix = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ]

    return mixer(inv_mix_matrix, state)


def key_expansion(key):
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    key_schedule = [key[i:i + 4] for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = key_schedule[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [s_box[b] for b in temp]
            temp[0] ^= rcon[(i // 4) - 1]
        key_schedule.append([key_schedule[i - 4][j] ^ temp[j] for j in range(4)])

    return [key_schedule[i:i + 4] for i in range(0, 44, 4)]


def aes_encrypt_block(block, key):
    state = bytes_to_matrix(block)
    round_keys = key_expansion(key)

    state = add_round_key(state, round_keys[0])

    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return matrix_to_bytes(state)


def aes_decrypt_block(block, key):
    state = bytes_to_matrix(block)
    round_keys = key_expansion(key)

    state = add_round_key(state, round_keys[10])

    for round_num in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return matrix_to_bytes(state)


def pkcs7_pad(data):
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data):
    padding_length = data[-1]
    if padding_length > 16 or padding_length == 0:
        raise ValueError("Invalid padding")

    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            raise ValueError("Invalid padding")

    return data[:-padding_length]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext, key, iv=None):
    if len(key) != 16:
        key = key[:16].ljust(16, b'\x00')

    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        iv = iv[:16].ljust(16, b'\x00')

    padded_data = pkcs7_pad(plaintext)
    blocks = [padded_data[i:i + 16] for i in range(0, len(padded_data), 16)]

    encrypted_blocks = []
    previous_block = iv

    for block in blocks:
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = aes_encrypt_block(xored_block, key)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return iv + b''.join(encrypted_blocks)


def decrypt_cbc(ciphertext, key):
    if len(key) != 16:
        key = key[:16].ljust(16, b'\x00')

    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Invalid ciphertext length")

    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]

    blocks = [encrypted_data[i:i + 16] for i in range(0, len(encrypted_data), 16)]

    decrypted_blocks = []
    previous_block = iv

    for block in blocks:
        decrypted_block = aes_decrypt_block(block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        decrypted_blocks.append(plaintext_block)
        previous_block = block

    padded_plaintext = b''.join(decrypted_blocks)
    return pkcs7_unpad(padded_plaintext)


def encrypt(message, key):
    return encrypt_cbc(message, key)


def decrypt(ciphertext, key):
    return decrypt_cbc(ciphertext, key)


def header():
    print("=" * 60)
    print("                      SuperEncrypt")
    print("               Advanced Encryption Standard")
    print("Encrypt and Decrypt Text Messages based on the Rijndael algorithm")
    print("=" * 70)
    print()


def get_input(prompt, input_type="text", allow_empty=False):
    while True:
        try:
            user_input = input(prompt).strip()
            if not user_input and not allow_empty:
                print("WARNING: Input cannot be empty. Please try again.")
                continue

            if input_type == "hex" and user_input:
                bytes.fromhex(user_input)

            return user_input
        except ValueError:
            print("WARNING: Invalid hexadecimal format. Please enter valid hex characters.")
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            exit(0)


def get_operation():
    print("Available Operations:")
    print("   1. Encrypt text message")
    print("   2. Decrypt hex ciphertext")
    print("   3. Encrypt from file")
    print("   4. Decrypt to file")
    print()

    while True:
        try:
            choice = input("Select operation (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                return ['encrypt', 'decrypt', 'encrypt_file', 'decrypt_file'][int(choice) - 1]
            print("WARNING: Please enter a number between 1 and 4.")
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            exit(0)


def encryption():
    print("\nENCRYPTION MODE")
    print("-" * 30)

    message = get_input("Enter message to encrypt: ")
    key = get_input("Enter encryption key: ")

    print(f"\nInput length: {len(message)} characters")
    print("Encrypting...")

    try:
        result = encrypt(message.encode('utf-8'), key.encode('utf-8'))
        print("\nEncryption successful!")
        print(f"Encrypted (hex): {result.hex().upper()}")
        print(f"Output length: {len(result)} bytes")
        print(f"Blocks processed: {(len(result) - 16) // 16}")
    except Exception as e:
        print(f"ERROR: Encryption failed - {str(e)}")


def decryption():
    print("\nDECRYPTION MODE")
    print("-" * 30)

    ciphertext_hex = get_input("Enter hex ciphertext to decrypt: ", "hex")
    key = get_input("Enter decryption key: ")

    print(f"\nInput length: {len(ciphertext_hex)} hex characters ({len(ciphertext_hex) // 2} bytes)")
    print("Decrypting...")

    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        result = decrypt(ciphertext_bytes, key.encode('utf-8'))
        decoded_result = result.decode('utf-8', errors='replace')

        print("\nDecryption successful!")
        print(f"Decrypted message: {decoded_result}")
        print(f"Output length: {len(decoded_result)} characters")
        print(f"Blocks processed: {(len(ciphertext_bytes) - 16) // 16}")
    except ValueError as e:
        print(f"ERROR: Invalid input format - {str(e)}")
    except Exception as e:
        print(f"ERROR: Decryption failed - {str(e)}")


def file_encryption():
    print("\nFILE ENCRYPTION MODE")
    print("-" * 30)

    input_file = get_input("Enter input file path: ")
    output_file = get_input("Enter output file path: ")
    key = get_input("Enter encryption key: ")

    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        print(f"\nFile size: {len(data)} bytes")
        print("Encrypting file...")

        encrypted_data = encrypt(data, key.encode('utf-8'))

        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        print("\nFile encryption successful!")
        print(f"Input: {input_file} ({len(data)} bytes)")
        print(f"Output: {output_file} ({len(encrypted_data)} bytes)")
        print(f"Blocks processed: {(len(encrypted_data) - 16) // 16}")

    except FileNotFoundError:
        print(f"ERROR: File not found - {input_file}")
    except PermissionError:
        print(f"ERROR: Permission denied accessing files")
    except Exception as e:
        print(f"ERROR: File encryption failed - {str(e)}")


def file_decryption():
    print("\nFILE DECRYPTION MODE")
    print("-" * 30)

    input_file = get_input("Enter encrypted file path: ")
    output_file = get_input("Enter output file path: ")
    key = get_input("Enter decryption key: ")

    try:
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        print(f"\nEncrypted file size: {len(encrypted_data)} bytes")
        print("Decrypting file...")

        decrypted_data = decrypt(encrypted_data, key.encode('utf-8'))

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        print("\nFile decryption successful!")
        print(f"Input: {input_file} ({len(encrypted_data)} bytes)")
        print(f"Output: {output_file} ({len(decrypted_data)} bytes)")
        print(f"Blocks processed: {(len(encrypted_data) - 16) // 16}")

    except FileNotFoundError:
        print(f"ERROR: File not found - {input_file}")
    except PermissionError:
        print(f"ERROR: Permission denied accessing files")
    except Exception as e:
        print(f"ERROR: File decryption failed - {str(e)}")


def ask_continue():
    print("\n" + "-" * 60)
    while True:
        try:
            choice = input("Would you like to perform another operation? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                return False
            print("WARNING: Please enter 'y' for yes or 'n' for no.")
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            exit(0)


def main():
    header()

    try:
        while True:
            operation = get_operation()

            if operation == "encrypt":
                encryption()
            elif operation == "decrypt":
                decryption()
            elif operation == "encrypt_file":
                file_encryption()
            elif operation == "decrypt_file":
                file_decryption()

            if not ask_continue():
                break

    except Exception as e:
        print(f"\nERROR: An unexpected error occurred - {str(e)}")

    print("\n" + "=" * 60)
    print("           Thank you for using SuperEncrypt!")
    print("=" * 60)


if __name__ == '__main__':
    main()
