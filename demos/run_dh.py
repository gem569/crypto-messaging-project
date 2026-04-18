from core.diffie_hellman import (generate_private_key,
                                 generate_public_key,
                                 compute_shared_secret)

from core.encryption import xor_encrypt_decrypt

def run_dh(g, p):
    #Alice's keys
    a_private = generate_private_key(p)
    a_public = generate_public_key(a_private, g, p)

    #Bob's keys
    b_private = generate_private_key(p)
    b_public = generate_public_key(b_private, g, p)

    #Shared secret
    alice_secret = compute_shared_secret(b_public, a_private, p)
    bob_secret = compute_shared_secret(a_public, b_private, p)

    print("Shared secret match:", alice_secret == bob_secret)

    #Including messaging
    message = "hello bob"

    encrypted = xor_encrypt_decrypt(alice_secret, message)
    decrypted = xor_encrypt_decrypt(bob_secret, encrypted)

    print("\nOriginal message:", message)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    g = 5
    p = 23

    run_dh(g, p)