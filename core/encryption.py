def xor_encrypt_decrypt(key, message):
    """
    Symmetric cipher using XOR.
    Same function encrypts and decrypts.
    """

    result = []

    for i in range(len(message)):
        #cycle key if shorter than message
        key_char = str(key)[i % len(str(key))]

        #XOR between characters
        encrypted_char = chr(ord(message[i]) ^ ord(key_char))
        result.append(encrypted_char)

    return ''.join(result)