from core.diffie_hellman import (generate_private_key,
                                 generate_public_key,
                                 compute_shared_secret)

from core.encryption import xor_encrypt_decrypt

from secure.secure_diffie_hellman import (sign, verify)

def run_secure_protocol(g, p):

    #Alice
    a_private = generate_private_key(p)
    a_public = generate_public_key(a_private, g, p)

    #Bob
    b_private = generate_private_key(p)
    b_public = generate_public_key(b_private, g, p)

    #Eve attempts MITM
    e_private = generate_private_key(p)

    fake_b_public = generate_public_key(e_private, g, p)
    fake_a_public = generate_public_key(e_private, g, p)

    # -- Key exchange -- #
    alice_secret = compute_shared_secret(b_public, a_private, p)
    bob_secret = compute_shared_secret(a_public, b_private, p)

    #eve's view
    eve_secret_alice = compute_shared_secret(a_public, e_private, p)
    eve_secret_bob = compute_shared_secret(b_public, e_private, p)

    # -- Messaging -- #
    message = "hello bob, secure world"

    encrypted = xor_encrypt_decrypt(alice_secret, message)
    intercepted = encrypted  #Eve sees ciphertext

    bob_decrypted = xor_encrypt_decrypt(bob_secret, intercepted)
    eve_decrypted = xor_encrypt_decrypt(eve_secret_alice, intercepted)

    # -- Security evaluation -- #
    attack_detected = (
        fake_a_public != a_public or fake_b_public != b_public
    )

    # -- Results -- #
    print("\n--- SECURE PROTOCOL EXPERIMENT ---\n")

    print("Message:", message)
    print("Encrypted:", encrypted)

    print("\nBob decrypted:", bob_decrypted)
    print("Eve decrypted:", eve_decrypted)

    print("\nMatch (Bob):", message == bob_decrypted)
    print("Eve recovered message:", eve_decrypted == message)

    print("\nAttack detected:", attack_detected)

    if attack_detected:
        print("Result: MITM attempted (protocol insecure without authentication)")
    else:
        print("Result: No attack detected (ideal scenario)")
        
# -- Run test -- #
if __name__ == "__main__":
    #Set g and p
    g = 5
    p = 23
    run_secure_protocol(g, p)