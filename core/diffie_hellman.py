#Importing random numbers
import random

#Public parameters (in real systems, large and fixed)
p = 23
g = 5

def generate_private_key(p):
    """
    Each party chooses a secret integer.
    """
    return random.randint(2, p-2)

def generate_public_key(private_key, g, p):
    """
    Computes public key: g^pk mod p
    """
    return pow(g, private_key, p)

def compute_shared_secret(other_public_key, private_key, p):
    """
    Computes shared secret: (other public)^private mod p
    """
    return pow(other_public_key, private_key, p)

def dh():
    # Alice
    a_private = generate_private_key(p)
    a_public = generate_public_key(a_private, g, p)

    # Bob
    b_private = generate_private_key(p)
    b_public = generate_public_key(b_private, g, p)

    # Shared secrets
    alice_secret = compute_shared_secret(b_public, a_private, p)
    bob_secret = compute_shared_secret(a_public, b_private, p)

    print("Alice secret:", alice_secret)
    print("Bob secret:  ", bob_secret)

    print("Match:", alice_secret == bob_secret)

if __name__ == "__main__":
    dh()