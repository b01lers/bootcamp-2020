from pwn import *  # NOQA

flag = b"flag{AAAAAAAAAAA}"
flag = bytes(bin(int(binascii.hexlify(flag), 16)), 'utf8')


class GuessIterator:

    def __init__(self):
        self.known_part = b""
        self.first_block = True
        self.i = -1

    def know_guess(self):
        self.known_part = self.current_guess()
        self.first_block = False
        self.i = -1

    def current_guess(self):
        if self.first_block:
            guess = bytes(bin(self.i).rjust(16, ' '), 'utf8')
        else:
            guess = bytes(bin(self.i)[2:].rjust(16, '0'), 'utf8')

        return self.known_part + guess

    def __iter__(self):
        return self

    def __next__(self):
        self.i += 1

        guess = self.current_guess()

        return guess


guessing = GuessIterator()
best_index = 0


def take_guess():
    return next(guessing)


def wrong_byte_feedback(index):
    global best_index
    if index is None:  # No wrong byte
        guessing.know_guess()
        best_index += 16
    elif index % 16 == 0 and index > best_index:
        guessing.know_guess()
        best_index += 16


# GAME ########################

p = process(['python3', './remote.py'])


try:
    while True:
        p.sendline(take_guess())
        result = p.recvline()
        i = 0
        for c in result:
            if c == ord('0'):
                i += 1
            else:
                break
        i = i // 2
        if i % 16 == 0 and i > best_index:
            print(guessing.current_guess())
        wrong_byte_feedback(i)
except Exception as e:
    print(guessing.current_guess())
    print(binascii.unhexlify(hex(int(str(guessing.current_guess(), 'utf8').strip()[2:], 2))[:2]))
