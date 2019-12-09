import random
from base64 import b64decode, b64encode


CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

import sys

def score(text):
    score = 0
    for c in text.lower():
        score += CHARACTER_FREQ.get(chr(c), 0)
    return score

def xor(mensaje, key):
    salida = b''
    for char in mensaje:
        salida += bytes([char ^ key])
    return salida

def break_single_key_xor(c):
    max_score = 0
    key = None

    for i in range(256):
        plainText = xor(c, i)
        actualScore = score(plainText)
        if actualScore > max_score:
            max_score = actualScore
            key = chr(i)
    return key
            

def main():
    try:
        file = "BreakRepeatingByteKey.txt"
        with open(file) as input_file:
            data = input_file.read()
    except:
        print("El archivo BreakRepeatingByteKey.txt no existe. Debemos crearlo con el texto a cifrar")
    else:
        print("##########################")
        print("PADDING ORACLE ATTACK")
        print("##########################")
        print("\n")

        print("El texto a cifrar es: " + data)
        print("El valor ASCII de la llave a utilizar es: ")
        key = random.randint(0,255)
        print(key)
        print("El texto cifrado quedaría del siguiente modo: ")
        clearText = bytes(data, 'utf-8')
        cipherText = xor(clearText, key)
        print(b64encode(cipherText))
        print("\n")

        print("El valor ASCII de la llave conseguida por el ataque es: ")
        keyattack = break_single_key_xor(cipherText)
        print(ord(keyattack))
        print("El texto desifrado conseguido por el ataque es: ")
        print(xor(cipherText, ord(keyattack)))

if __name__ == '__main__':
    main()


