#!/usr/bin/python3

import sys
import random
from base64 import b64decode
from Crypto.Cipher import AES

def detect_cipher(ciphertext):
    chunks = [ciphertext[i:i + AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    if (number_of_duplicates > 0):
        return "ECB"
    else:
        return "CBC"

def isPkcs7Padded(data):
    lastData = data[-1]
    for i in range(1, int(lastData)+1):
        if (data[-i] != lastData):
            return False
    return True

def encrypt_AES_128_ECB(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def paddPKCS7(data, paddingSize):
    dataSize = len(data)
    if(dataSize == paddingSize):
        return data
    else:
        distance = paddingSize - dataSize % paddingSize
        for i in range(distance):
            data = data + bytes([distance]) 
    return data

def unpaddPKCS7(data):
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")
    if not isPkcs7Padded(data):
        return data
    return data[:-data[-1]]


def encryption_oracle(INPUT):
    plaintext = paddPKCS7(INPUT + SECRET.encode(), AES.block_size)
    ciphertext = encrypt_AES_128_ECB(plaintext, KEY)
    return ciphertext

def get_block_cipher_size():
    ciphertext = encryption_oracle(b'')
    originalTam = len(ciphertext)
    for i in range (256):
        INPUT = bytes([0]*i)
        ciphertext = encryption_oracle(INPUT)
        tam = len(ciphertext)
        if(originalTam != tam):
            return tam - originalTam


def get_byte_by_byte(blockSize, secretPlainText, i):
    prefixLenght = ((blockSize - (i % blockSize))-1)
    prefix = bytes([0] * prefixLenght)
    ciphertextWithPrefix = encryption_oracle(prefix)
    lenghtBlock = prefixLenght + i + 1
    for i in range(256):
        blockToTry = b''
        blockToTry = prefix + secretPlainText + bytes([i])
        ciphertextToTry = encryption_oracle(blockToTry)
        if (ciphertextToTry[:lenghtBlock] == ciphertextWithPrefix[:lenghtBlock]):
            return bytes([i])
    return b''

def byte_at_a_time_attack():
    blockSize = get_block_cipher_size()
    checkECBtext = encryption_oracle(bytes([0] * 64))
    cipherType = detect_cipher(checkECBtext)
    if(cipherType == "ECB"):
        textToDecryptLenght = len(encryption_oracle(b''))
        secretPlainText = b''
        for i in range(textToDecryptLenght):
            secretPlainText += get_byte_by_byte(blockSize, secretPlainText, i)         
    else:
        print("It should be ECB")
    return secretPlainText


def main():
    clearText = byte_at_a_time_attack()

    print("##########################")
    print("BYTE AT A TIME ECB ATTACK")
    print("##########################")
    print("\n")

    print("El texto a cifrar es: " + SECRET)
    print("La llave a utilizar es: " + KEY.decode())
    print("El texto cifrado quedaría del siguiente modo: " + str(encryption_oracle(b'')))
    #print(str(encryption_oracle(b'')))
    print("\n")

    print("El texto desifrado conseguido por el ataque es: " + unpaddPKCS7(clearText).decode())


#SECRET = "Rollin in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
#KEY = b'A\xb3\xc0u\x8bP\xe8\xe2\x92\xb9x\x14-\x16Dm'
try:
    if len(sys.argv[1]) == 16:
        #KEY = b"THIS IS A RANDOM"
        KEY = sys.argv[1].encode()
        with open("ByteAtATimeECB.txt") as inputFile:
            SECRET = inputFile.read()
    else:
        raise Exception('Introduce como argumento una llave de longitud 16 bytes')
except:
    print("Introduce como argumento una llave de longitud 16 bytes")
    exit()


if __name__ == "__main__":
    main()