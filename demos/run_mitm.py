

from core.diffie_hellman import (generate_private_key,
                                generate_public_key,
                                compute_shared_secret)

from core.encryption import xor_encrypt_decrypt

from attacks.mitm_attack import (setup_true_parties,
                                 perform_mitm_interception)

# -- Running full attack -- #
def run_mitm_attack(g, p):

    #True parties generate keys
    a_private, a_public, b_private, b_public = setup_true_parties(g, p)

    #Eve sets up her own keys
    e_private_a, e_private_b, e_public_a, e_public_b = perform_mitm_interception(g, p)

    #Alice thinks she is talking to Bob (but gets Eve's key) 
    alice_secret = compute_shared_secret(e_public_b, a_private, p)

    #Bob thinks he is talking to Alice (but gets Eve's key)
    bob_secret = compute_shared_secret(e_public_a, b_private, p)

    #Eve computes both shared secrets
    eve_secret_with_alice = compute_shared_secret(a_public, e_private_b, p)
    eve_secret_with_bob = compute_shared_secret(b_public, e_private_a, p)

    # -- Message being sent -- #
    message = "hello bob, this is alice"

    #Alice encrypts using what she thinks is shared secret with Bob
    encrypted_msg = xor_encrypt_decrypt(alice_secret, message)

    #Eve intercepts ciphertext
    intercepted_msg = encrypted_msg

    #Bob decrypts using his (compromised) shared secret
    bob_decrypted = xor_encrypt_decrypt(bob_secret, intercepted_msg)

    #Eve decrypts using her Alice-side secret
    eve_decrypted = xor_encrypt_decrypt(eve_secret_with_alice, intercepted_msg)

    # - Results - #
    print("\n--- MITM ATTACK RESULTS ---\n")

    print("Alice secret:       ", alice_secret)
    print("Bob secret:         ", bob_secret)
    print("Eve ↔ Alice secret: ", eve_secret_with_alice)
    print("Eve ↔ Bob secret:   ", eve_secret_with_bob)

    print("\nAttack success:", alice_secret == eve_secret_with_alice and bob_secret == eve_secret_with_bob)

    #Adding message layer
    print("\n--- MESSAGE LAYER ---\n")

    print("Original message:", message)
    print("Intercepted ciphertext:", intercepted_msg)

    print("Bob decrypted:", bob_decrypted)
    print("Eve decrypted:", eve_decrypted)

    print("\nMessage attack success:", eve_decrypted == message)

# -- Run test -- #
if __name__ == "__main__":
    #Set g and p
    g = 5
    p = 23
    run_mitm_attack(g, p)