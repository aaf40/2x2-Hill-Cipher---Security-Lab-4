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

def cipher_decryption(cipher, key):
    if len(cipher) % 2 != 0:
        cipher += 'A'

    cipher = cipher.upper().replace(" ", "")  
    num_representation = [ord(char) - ord('A') for char in cipher]
    cipher_matrix = np.array(num_representation).reshape(-1, 2)  

    if len(key) != 4:
        raise ValueError("Key must consist of exactly 4 characters.")
    key_matrix = np.array([ord(char) - ord('A') for char in key.upper()]).reshape(2, 2)

    det = int(np.round(np.linalg.det(key_matrix)))  
    if np.gcd(det, 26) != 1:
        raise ValueError("Invalid key: determinant {} is not coprime with 26.".format(det))

    inv_det = pow(det, -1, 26)

    cofactor_matrix = np.array([[ key_matrix[1, 1], -key_matrix[0, 1]], [-key_matrix[1, 0],  key_matrix[0, 0]]])
    adjugate_matrix = cofactor_matrix

    inverse_key_matrix = (inv_det * adjugate_matrix) % 26

    decrypted_numeric = (inverse_key_matrix @ cipher_matrix.T) % 26  
    decrypted_text = ''.join(chr(num + ord('A')) for num in decrypted_numeric.flatten())  

    print("Decrypted text:", decrypted_text)
    return decrypted_text


def main():
    if len(sys.argv) != 3:
        print("Usage: python <script.py> <'plaintext'> <key>")
        sys.exit(1)

    # plain_text = sys.argv[1]
    # encryption_key = sys.argv[2]
    # cipher_encryption(plain_text, encryption_key)

    cipher_text = sys.argv[1]
    decryption_key = sys.argv[2]
    cipher_decryption(cipher_text, decryption_key)

if __name__ == "__main__":
    main()