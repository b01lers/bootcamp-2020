from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

flag = b"flag{AAAAAAAAAA}"
flag = bytes(bin(int(binascii.hexlify(flag), 16)), 'utf8')
key = get_random_bytes(16)


def encrypt_new_message(msg):
    iv = b"AAAAAAAAAAAAAAAA"
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    plaintext = msg
    while len(plaintext) % 16 != 0:
        plaintext = b' ' + plaintext

    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, plaintext


def xor_guess_flag(guess_ct, flag_ct):
    result = b''
    for i in range(min(len(flag_ct), len(guess_ct))):
        result = result + bytes(chr(guess_ct[i] ^ flag_ct[i]), 'utf8')

    return result

# GAME ########################


def game_step():
    ct, pt = encrypt_new_message(flag)
    guess = bytes(input(), 'utf8')
    ct_guess, pt_guess = encrypt_new_message(guess)
    if pt_guess == pt:
        return True

    print(str(binascii.hexlify(xor_guess_flag(ct_guess, ct)), 'utf8'))

    return False


def game():
    for i in range(1000000):
        if game_step():
            return True

    return False


print(game())
