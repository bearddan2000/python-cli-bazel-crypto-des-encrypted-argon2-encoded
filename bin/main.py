#!/usr/bin/env python
from argon2 import PasswordHasher
from des import DesKey

def encryptAlg(password):
    # DES 8 bit
    key = DesKey(b"A quick ")
    # password should be length div by 8, 16, 24
    enc = bytes(password, encoding='utf-8')
    return key.encrypt(enc, padding=True)

def hashPsw(ph, password):
    encryptedStr = encryptAlg(password)
    return ph.hash(encryptedStr)

def check_password(ph, password, hashed):
    try:
        ph.verify(hashed, password)
        print("[COMP] true")
    except:
        print("[COMP] false")


def comp(ph, psw1, psw2):
    hash1 = hashPsw(ph, psw1)
    encryptedStr = encryptAlg(psw2)
    print( "[COMP] psw1 = %s, psw2 = %s" % (psw1, psw2));
    check_password(ph, encryptedStr, hash1)

def printPsw(ph, password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(ph, password));

def main():
    ph = PasswordHasher()
    psw1 = 'pass123';
    psw2 = '123pass';
    printPsw(ph, psw1)
    printPsw(ph, psw2)
    comp(ph, psw1, psw1)
    comp(ph, psw1, psw2)

if __name__ == '__main__':
    main()
