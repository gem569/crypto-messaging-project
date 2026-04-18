from core.diffie_hellman import (generate_private_key,
                                 generate_public_key,
                                 compute_shared_secret)

# -- Setting up true parties -- #
def setup_true_parties(g, p):
    #Alice's keys
    a_private = generate_private_key(p)
    a_public = generate_public_key(a_private, g, p)

    #Bob's keys
    b_private = generate_private_key(p)
    b_public = generate_public_key(b_private, g, p)

    return a_private, a_public, b_private, b_public

# -- Eve intercepts channel -- #
def perform_mitm_interception(g, p):

    #Eve creates her own keys for both sides
    e_private_a = generate_private_key(p)
    e_private_b = generate_private_key(p)

    e_public_a = generate_public_key(e_private_a, g, p)
    e_public_b = generate_public_key(e_private_b, g, p)

    return e_private_a, e_private_b, e_public_a, e_public_b

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

    # - Results - #
    print("\n--- MITM ATTACK RESULTS ---\n")

    print("Alice secret:       ", alice_secret)
    print("Bob secret:         ", bob_secret)
    print("Eve ↔ Alice secret: ", eve_secret_with_alice)
    print("Eve ↔ Bob secret:   ", eve_secret_with_bob)

    print("\nAttack success:", alice_secret == eve_secret_with_alice and bob_secret == eve_secret_with_bob)

# -- Run test -- #
if __name__ == "__main__":
    #Set g and p
    g = 5
    p = 23
    run_mitm_attack(g, p)