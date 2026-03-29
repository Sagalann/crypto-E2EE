from nacl.public import PrivateKey, PublicKey, Box
import base64

def generate_identity_keypair():
    priv = PrivateKey.generate()
    return priv, priv.public_key

def b64_encode_key(key):
    return base64.b64encode(bytes(key)).decode('utf-8')

def b64_decode_public_key(b64: str) -> PublicKey:
    return PublicKey(base64.b64decode(b64))

def b64_decode_private_key(b64: str) -> PrivateKey:
    return PrivateKey(base64.b64decode(b64))

def encrypt_message(sender_private: PrivateKey, recipient_public: PublicKey, message: str) -> str:
    box = Box(sender_private, recipient_public)
    encrypted = box.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(recipient_private: PrivateKey, sender_public: PublicKey, ciphertext: str) -> str:
    box = Box(recipient_private, sender_public)
    encrypted = base64.b64decode(ciphertext)
    decrypted = box.decrypt(encrypted)
    return decrypted.decode('utf-8')