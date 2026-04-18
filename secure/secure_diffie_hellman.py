from core.diffie_hellman import (generate_private_key,
                                 generate_public_key,
                                 compute_shared_secret)

from core.encryption import xor_encrypt_decrypt

# -- Fake "signature" system -- #
def sign(value, private_key):
    return hash((value, private_key))

def verify(value, signature, public_key):
    #In real crypto this would use public key crypto
    return signature == hash((value, public_key))