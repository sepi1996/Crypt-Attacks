from Crypto.Cipher import AES
from random import randint
from Crypto import Random
from Crypto.Cipher.AES import block_size, key_size
from base64 import b64decode, b64encode



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

def isPkcs7Padded(data):
    lastData = data[-1]
    for i in range(1, int(lastData)+1):
        if (data[-i] != lastData):
            return False
    return True

def pkcs7_pad(message, block_size):
    if len(message) == block_size:
        return message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)



def xor(b1, b2):
	b = bytearray(len(b1))
	for i in range(len(b1)):
		b[i] = b1[i] ^ b2[i]
	return b

def encrypt_AES_128_ECB(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def encrypt_AES_128_CBC(data, key, iv):
    cypertext = b''
    previousBlock = b''

    for i in range(0, len(data), AES.block_size):
        block = bytes(data[i:i + AES.block_size])
        block = paddPKCS7(block, AES.block_size)
        if (i == 0):
            block = xor(block, iv)
        else:
            block = xor(block, previousBlock)
        block = encrypt_AES_128_ECB(block, key)        
        cypertext += block
        previousBlock = block
    return cypertext


def decrypt_AES_128_CBC(data, key, iv, unpad=True):
    plaintext = b''
    prev = iv

    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = decrypt_AES_128_ECB(curr_ciphertext_block, key)
        plaintext += xor(prev, decrypted_block)
        prev = curr_ciphertext_block
    if unpad:
        return unpaddPKCS7(plaintext)
    else:
        return plaintext


def decrypt_AES_128_ECB(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpaddPKCS7(cipher.decrypt(data))


class Oracle:

    def __init__(self, userInput):
        self.iv = Random.new().read(block_size)
        self._key = Random.new().read(key_size[0])
        self.userInput = userInput

    def get_encrypted_message(self):
        return encrypt_AES_128_CBC(self.userInput.encode(), self._key, self.iv)
    
    def decrypt_and_check_padding(self, ciphertext, iv):
        plaintext = decrypt_AES_128_CBC(ciphertext, self._key, iv, False)
        return isPkcs7Padded(plaintext)


def create_forced_previous_block(iv, guessed_byte, padding_len, found_plaintext):

    indexCharToTry = len(iv) - padding_len
    charToTry = iv[indexCharToTry] ^ guessed_byte ^ padding_len
    finalIV = iv[:indexCharToTry] + bytes([charToTry])

    i = 0
    for k in range(block_size - padding_len + 1, block_size):
        charToTry = iv[k] ^ found_plaintext[i] ^ padding_len
        finalIV = finalIV + bytes([charToTry])
        i += 1

    return finalIV

def theFinalCandidate(possible_last_bytes, previousCiphertextBlock, ciphertextBlock, padding_len, plaintextBlock, oracle):
    for byte in possible_last_bytes:
        for j in range(256):
            forced_iv = create_forced_previous_block(previousCiphertextBlock, j, padding_len + 1, bytes([byte]) + plaintextBlock)
            if oracle.decrypt_and_check_padding(ciphertextBlock, forced_iv):
                return [byte]

def attack_padding_oracle(ciphertext, oracle):

    finalPlainText = b''
    ciphertextBlocks = [oracle.iv] + [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    for c in range(1, len(ciphertextBlocks)):
        plaintextBlock = b''  
        for i in range(block_size - 1, -1, -1):
            padding_len = len(plaintextBlock) + 1
            possible_last_bytes = []
            for j in range(256):
                forced_iv = create_forced_previous_block(ciphertextBlocks[c - 1], j, padding_len, plaintextBlock)
                if oracle.decrypt_and_check_padding(ciphertextBlocks[c], forced_iv):
                    possible_last_bytes += bytes([j])

            if len(possible_last_bytes) != 1:
                possible_last_bytes = theFinalCandidate(possible_last_bytes, ciphertextBlocks[c - 1], ciphertextBlocks[c], padding_len, plaintextBlock, oracle)

            plaintextBlock = bytes([possible_last_bytes[0]]) + plaintextBlock
        finalPlainText += plaintextBlock
    return unpaddPKCS7(finalPlainText)


def main():

    try:
        file = "PaddingOracle.txt"
        with open(file) as input_file:
            data = input_file.read()
    except:
        print("El archivo PaddingOracle.txt no existe. Debemos crearlo con el texto a cifrar")
    else:
        dataTobase64 = b64encode(bytes(data, 'utf-8'))
        stringBase64 = dataTobase64.decode("utf-8")
        oracle = Oracle(stringBase64)
        result = attack_padding_oracle(oracle.get_encrypted_message(), oracle)

        print("##########################")
        print("PADDING ORACLE ATTACK")
        print("##########################")
        print("\n")

        print("El texto a cifrar es: " + data)
        print("La llave a utilizar es: ")
        print(b64encode(oracle._key))
        print("El IV a utilizar es: ")
        print(b64encode(oracle.iv)) 
        print("El texto cifrado quedaría del siguiente modo: ")
        print(b64encode(oracle.get_encrypted_message()))
        print("\n")

        print("El texto desifrado conseguido por el ataque es: ")
        print(b64decode(result.decode()))

if __name__ == '__main__':
    main()