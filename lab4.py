from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
import base64

def generate_valid_3des_key():
    while True:
        try:
            key = get_random_bytes(24)  # 24 bytes = 192 bits
            DES3.new(key, DES3.MODE_CBC, get_random_bytes(8))
            return key
        except ValueError:
            continue

def adjust_key(key, required_length, is_3des=False):
    """Ajusta la longitud de la clave al tamaño requerido"""
    if is_3des:
        try:
            if len(key) < required_length:
                key = key + get_random_bytes(required_length - len(key))
            key = key[:required_length]
            DES3.new(key, DES3.MODE_CBC, get_random_bytes(8))
            return key
        except ValueError:
            print("La clave proporcionada no es válida para 3DES. Generando una nueva clave...")
            return generate_valid_3des_key()
    else:
        if len(key) < required_length:
            return key + get_random_bytes(required_length - len(key))
        return key[:required_length]

def pad_text(text, block_size=8):
    """Aplica padding PKCS5 al texto para que sea múltiplo del tamaño de bloque"""
    padding_length = block_size - (len(text) % block_size)
    padding = bytes([padding_length]) * padding_length
    return text + padding

def unpad_text(text):
    """Remueve el padding PKCS5 del texto descifrado"""
    padding_length = text[-1]
    if padding_length > len(text):
        raise ValueError("Padding length is greater than text length")
    return text[:-padding_length]

class CipherWrapper:
    def __init__(self, algorithm_name, key_size, iv_size):
        self.algorithm_name = algorithm_name
        self.key_size = key_size
        self.iv_size = iv_size
        
    def encrypt(self, key, iv, plaintext):
        key = adjust_key(key, self.key_size)
        iv = adjust_key(iv, self.iv_size)
    
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        padded_text = pad_text(plaintext)
        
        if self.algorithm_name == "DES":
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif self.algorithm_name == "3DES":
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        else:  # AES-256
            cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Cifrar y codificar en base64
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()
    
    def decrypt(self, key, iv, ciphertext):
        key = adjust_key(key, self.key_size)
        iv = adjust_key(iv, self.iv_size)
        ciphertext = base64.b64decode(ciphertext)
        
        if self.algorithm_name == "DES":
            cipher = DES.new(key, DES.MODE_CBC, iv)
        elif self.algorithm_name == "3DES":
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
        else:  # AES-256
            cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Descifrar y remover padding
        decrypted = cipher.decrypt(ciphertext)
        return unpad_text(decrypted).decode()

def main():
    ciphers = {
        "DES": CipherWrapper("DES", 8, 8),
        "3DES": CipherWrapper("3DES", 24, 8),
        "AES-256": CipherWrapper("AES-256", 32, 16)
    }
    
    print("Seleccione el algoritmo (DES, 3DES, AES-256):")
    algorithm = input().strip().upper()
    
    print("Ingrese la clave (en texto):")
    key = input().strip().encode()
    
    print("Ingrese el vector de inicialización (IV) (en texto):")
    iv = input().strip().encode()
    
    print("Ingrese el texto a cifrar:")
    plaintext = input().strip()
    
    if algorithm not in ciphers:
        print("Algoritmo no válido")
        return
    
    cipher = ciphers[algorithm]
    
    # Mostrar clave ajustada
    adjusted_key = adjust_key(key, cipher.key_size)
    print(f"\nClave ajustada (hex): {adjusted_key.hex()}")
    
    # Cifrar
    encrypted = cipher.encrypt(key, iv, plaintext)
    print(f"\nTexto cifrado (base64): {encrypted}")
    
    # Descifrar
    decrypted = cipher.decrypt(key, iv, encrypted)
    print(f"\nTexto descifrado: {decrypted}")

if __name__ == "__main__":
    main()