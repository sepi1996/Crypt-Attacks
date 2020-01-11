import re
from Crypto.Hash import SHA
from binascii import unhexlify
from Crypto.Util.number import getPrime, getStrongPrime



def mod_inv(a, n):
	t, r = 0, n
	new_t, new_r = 1, a

	while new_r != 0:
		quotient = r // new_r
		t, new_t = new_t, t - quotient * new_t
		r, new_r = new_r, r - quotient * new_r
	if r > 1:
		raise Exception("a no es invertible")
	if t < 0:
		t = t + n
	return t

class RSA:
	def __init__(self, size):
		#self.e = 65537
		self.e = 3
		if size < 1024:
			p = getPrime(size // 2)
			q = getPrime(size // 2)
		else:
			p = getStrongPrime(size // 2, self.e)
			q = getStrongPrime(size // 2, self.e)
		self.n = p * q
		self.phi = (p - 1) * (q - 1)
		self.d = mod_inv(self.e, self.phi)

	def encrypt(self, binary_data):
		int_data = int.from_bytes(binary_data, byteorder='big')
		return pow(int_data, self.e, self.n)

	def decrypt(self, encrypted_int_data):
		int_data = pow(encrypted_int_data, self.d, self.n)
		return int_to_bytes(int_data)

def int_to_bytes(n):
	return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def find_cube_root(n):
	lo = 0
	hi = n

	while lo < hi:
		mid = (lo + hi) // 2
		if mid**3 < n:
			lo = mid + 1
		else:
			hi = mid

	return lo
# 15-byte ASN.1 value for SHA1 (from rfc 3447)
ASN1_SHA1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'


class RSASignature(RSA):

    def sign(self, message):
        return self.decrypt(int.from_bytes(message, byteorder='big'))

    def verifySign(self, encrypted_signature, message):

        signature = b'\x00' + int_to_bytes(self.encrypt(encrypted_signature))
        print("La firma tras aplicar el descifrado es: ", signature)
        r = re.compile(b'\x00\x01\xff+?\x00.{15}(.{20})', re.DOTALL)
        m = r.match(signature)
        if not m:
            return False
        hashed = m.group(1)
        print("El hash obtenido es", hashed)
        print("El Hash real es:", SHA.new(message).hexdigest())
        return hashed == unhexlify(SHA.new(message).hexdigest())

def fakeSignature(message, key_length):

    block = b'\x00\x01\xff\x00' + ASN1_SHA1 + unhexlify(SHA.new(message).hexdigest())
    garbage = (((key_length + 7) // 8) - len(block)) * b'\x00'
    block += garbage

    pre_encryption = int.from_bytes(block, byteorder='big')
    forged_sig = find_cube_root(pre_encryption)
    return int_to_bytes(forged_sig)


def main():
    message = b'hola'
    forged_signature = fakeSignature(message, 1024)

    print("##########################")
    print("Bleichenbacher's RSA firma digital Attack")
    print("##########################")


    print("El texto a firmar es: ")
    print(message)
    print("La firma (cifrada) con el padding falso creado es: ")
    print(forged_signature)

    assert RSASignature(1024).verifySign(forged_signature, message)


if __name__ == '__main__':
    main()