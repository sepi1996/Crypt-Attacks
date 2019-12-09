#!/usr/bin/python3

import sys
from base64 import b64decode, b64encode
from itertools import combinations

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

def score(text):
    score = 0
    for c in text.lower():
        score += CHARACTER_FREQ.get(chr(c), 0)
    return score

def encrypt_repeating_key_xor(mensaje, k):
    key = k * int((len(mensaje)/len(k)))
    resto = len(mensaje)%len(k)
    if resto != 0:
        for i in range(resto):
            key = key + k[i]
    key = bytearray(key, 'utf-8')

    ciphertext = bytes(xor(mensaje, key))
    return ciphertext

def break_single_key_xor(c):
    max_score = 0
    key = None

    for i in range(256):
        secuenciaBinaria = [i] * len(c)
        secuenciaBinaria = bytearray(secuenciaBinaria	)
        plainText = xor(c, secuenciaBinaria)
        actualScore = score(plainText)
        if actualScore > max_score:
            max_score = actualScore
            key = chr(i)
    return key

def xor(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b



def hamming_distance(b1, b2):
    distance = 0
    for b1_bit, b2_bit in zip(b1, b2):
        xor = b1_bit ^ b2_bit
        for bit in bin(xor):
            if bit == '1':
                distance += 1
    return distance


def key_Size(data):
    chunks = []
    normalized_distances = {}
    for key_size in range(2, 30):
        chunks.clear()
        distance = 0
        for i in range (4):
            chunks.append(data[(i*key_size):((i+1)*key_size)])
        pairs = combinations(chunks, 2)
        for (x, y) in pairs:
            distance += hamming_distance(x, y)
        
        distance /= 6
        normalized_distance = int(distance / key_size)

        normalized_distances[key_size] = normalized_distance

    theBestKeys = sorted(normalized_distances, key=normalized_distances.get)[:3]
    print ("Los posibles tam de llave son:")
    print (theBestKeys)
    return theBestKeys
    

def decrypt(keys_size, data):
    keys = []
    for key_size in keys_size:
        key = ""
        for i in range(key_size):
            data_segment = b''
            for j in range(int((len(data)/key_size))):
                data_segment += bytes([data[j*key_size + i]])
            key += break_single_key_xor(data_segment)
        keys.append(key)
    the_final_key = ""
    the_best_score = 0
    the_final_text = ""
    for k in keys:
        texto_a_analizar = encrypt_repeating_key_xor(data, k)
        resultado = score(texto_a_analizar)
        if resultado > the_best_score:
            the_best_score = resultado
            the_final_key = k
            the_final_text = texto_a_analizar
    print("La llave es: " + the_final_key)
    print("El texto es: " + the_final_text.decode('utf-8'))



def main():
    try:
        if len(sys.argv[1]) > 1 and len(sys.argv[1]) < 30:
            try:
                KEY = sys.argv[1]
                file = "BreakRepeatingKeyXOR.txt"
                with open(file) as input_file:
                    data = input_file.read()
            except:
                print("El archivo PaddingOracle.txt no existe. Debemos crearlo con el texto a cifrar")
            else:
                print("##########################")
                print("REPEATING KEY ATTACK")
                print("##########################")
                print("\n")

                print("El texto a cifrar es: " + data)
                print("La llave a utilizar es: ")
                print(KEY)
                data = bytes(data, 'utf-8')
                ciphertext = encrypt_repeating_key_xor(data, KEY)
                print("El texto cifrado es: ")
                print(b64encode(ciphertext))
                theBestKeys = key_Size(ciphertext)
                decrypt(theBestKeys, ciphertext)
                
                
        else:
            print("Introduce una llave con una longitud entre 2 y 30")
    except:
        print("Introduce una llave como argumento")
 
if __name__ == "__main__":
    main()


