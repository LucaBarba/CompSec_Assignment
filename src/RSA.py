from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from base64 import b64encode, b64decode
from hashlib import sha3_512

# Etapa I: Geração de chaves
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Cifração RSA com OAEP
def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decifração RSA com OAEP
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Etapa II: Assinatura
def sign_message(private_key, message):
    # Hash da mensagem usando SHA-3
    digest = sha3_512(message).digest()
    # Assinatura: cifração do hash
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return b64encode(signature)

# Etapa III: Verificação
def verify_signature(public_key, message, signature):
    # Decodificação da assinatura
    signature = b64decode(signature)
    # Hash da mensagem para comparação
    digest = sha3_512(message).digest()
    
    try:
        # Verificação da assinatura
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Exemplo de uso
if __name__ == "__main__":
    # Geração de chaves
    private_key, public_key = generate_keys()

    # Mensagem a ser assinada
    message = "Este é um documento importante.".encode('utf-8')

    # Assinatura
    signature = sign_message(private_key, message)
    print(f"Assinatura: {signature}")

    # Verificação da assinatura
    is_valid = verify_signature(public_key, message, signature)
    print(f"A assinatura é válida? {is_valid}")
