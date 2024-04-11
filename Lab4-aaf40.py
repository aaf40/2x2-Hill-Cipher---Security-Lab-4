import sys
import numpy as np

def cipher_encryption(plain, key):
    plain = plain.upper().replace(" ", "")
    if len(plain) % 2 != 0:
        plain += 'Z' 

    num_representation = [ord(char) - ord('A') for char in plain]
    message_matrices = np.array(num_representation).reshape(-1, 2)  

    if len(key) != 4:
        raise ValueError("Key must consist of exactly 4 characters.")
    key_matrix = np.array([ord(char) - ord('A') for char in key.upper()]).reshape(2, 2)
    print("Key matrix:\n", key_matrix)

    det = int(np.round(np.linalg.det(key_matrix)))
    if np.gcd(det, 26) != 1:
        raise ValueError("Invalid key: determinant {} is not coprime with 26.".format(det))
    
    encrypted_matrices = (key_matrix @ message_matrices.T) % 26  
    encrypted_numbers = encrypted_matrices.T.flatten()  
    encrypted_text = ''.join(chr(num + ord('A')) for num in encrypted_numbers)

    print("Encrypted text:", encrypted_text)
    return encrypted_text

def main():
    if len(sys.argv) != 3:
        print("Usage: python <script.py> <'plaintext'> <key>")
        sys.exit(1)

    plain_text = sys.argv[1]
    encryption_key = sys.argv[2]

    cipher_encryption(plain_text, encryption_key)

if __name__ == "__main__":
    main()