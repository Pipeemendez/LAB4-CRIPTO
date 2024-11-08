from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import binascii

def adjust_key(key):
    """Ajusta la clave a 8 bytes (64 bits) para DES."""
    if len(key) < 8:
        key += get_random_bytes(8 - len(key))
        print(f"Clave demasiado corta, completada a: {binascii.hexlify(key)}")
    elif len(key) > 8:
        key = key[:8]
        print(f"Clave demasiado larga, truncada a: {binascii.hexlify(key)}")
    return key

def adjust_nonce(nonce):
    """Ajusta el nonce (IV) a 8 bytes para DES."""
    if len(nonce) < 8:
        nonce += get_random_bytes(8 - len(nonce))
        print(f"Nonce demasiado corto, completado a: {binascii.hexlify(nonce)}")
    elif len(nonce) > 8:
        nonce = nonce[:8]
        print(f"Nonce demasiado largo, truncado a: {binascii.hexlify(nonce)}")
    return nonce

def encrypt(msg, key, nonce):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return ciphertext, tag

def decrypt(ciphertext, tag, key, nonce):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

# Solicitar datos al usuario
key_input = input("Ingrese la clave (en texto plano): ").encode('utf-8')
nonce_input = input("Ingrese el IV/Nonce (en texto plano): ").encode('utf-8')
message = input("Ingrese el mensaje a cifrar: ")

# Ajustar la clave y el nonce
key = adjust_key(key_input)
nonce = adjust_nonce(nonce_input)

# Mostrar la clave y nonce originales y ajustados
print(f"Clave ingresada: {binascii.hexlify(key_input)}")
print(f"Clave ajustada: {binascii.hexlify(key)}")
print(f"Nonce ingresado: {binascii.hexlify(nonce_input)}")
print(f"Nonce ajustado: {binascii.hexlify(nonce)}")

# Cifrar y descifrar el mensaje
ciphertext, tag = encrypt(message, key, nonce)
plaintext = decrypt(ciphertext, tag, key, nonce)

# Mostrar el texto cifrado y descifrado
print(f"Texto cifrado (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")
if not plaintext:
    print('El mensaje está corrupto!')
else:
    print(f'Texto descifrado: {plaintext}')
