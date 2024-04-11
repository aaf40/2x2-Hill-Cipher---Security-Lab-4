import sys
import numpy as np

def cipher_encryption(plain, key):
    plain = plain.upper().replace(" ", "")
    if len(plain) % 2 != 0:
        plain += 'Z'  # Append 'Z' to make the length even

    num_representation = [ord(char) - ord('A') for char in plain]
    message_matrices = np.array(num_representation).reshape(-1, 2).T

    if len(key) != 4:
        raise ValueError("Key must consist of exactly 4 characters.")
    key_matrix = np.array([ord(char) - ord('A') for char in key.upper()]).reshape(2, 2)
    print("Key matrix:\n", key_matrix)

    # Checking validity of the key
    # Finding determinant
    det = int(np.round(np.linalg.det(key_matrix)))  # Calculate the determinant of the key matrix
    if np.gcd(det, 26) != 1:
        raise ValueError("Invalid key: determinant {} is not coprime with 26.".format(det))
    
    inverse_det = pow(det, -1, 26)  # Calculate the modular inverse of the determinant

    # Finding multiplicative inverse and implementing steps to encrypt text
    encrypted_matrices = (key_matrix @ message_matrices) % 26  # Matrix multiplication and mod 26
    encrypted_numbers = encrypted_matrices.flatten()  # Flatten the matrix to a single array
    encrypted_text = ''.join(chr(num + ord('A')) for num in encrypted_numbers)  # Convert numbers back to letters

    print("Encrypted text:", encrypted_text)
    return encrypted_text

def main():
    if len(sys.argv) != 3:
        print("Usage: python <script.py> <'plaintext'> <key>")
        sys.exit(1)

    plain_text = sys.argv[1]
    encryption_key = sys.argv[2]

    encrypted_message = cipher_encryption(plain_text, encryption_key)
    print("Encrypted Message:", encrypted_message)

if __name__ == "__main__":
    main()