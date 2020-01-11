from Crypto.Util.number import getPrime, getStrongPrime

#RSA
def int_to_bytes(n):
	return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def mod_inv(a, n):
	t, r = 0, n
	new_t, new_r = 1, a

	while new_r != 0:
		quotient = r // new_r
		t, new_t = new_t, t - quotient * new_t
		r, new_r = new_r, r - quotient * new_r
	if r > 1:
		raise Exception("a is not invertible")
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


def rsa_broadcast_attack(ciphertexts):
	n0, n1, n2 = ciphertexts[0][1], ciphertexts[1][1], ciphertexts[2][1]
	c0, c1, c2 = ciphertexts[0][0], ciphertexts[1][0], ciphertexts[2][0]
	
	m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

	t0 = (c0 * m0 * mod_inv(m0, n0))
	t1 = (c1 * m1 * mod_inv(m1, n1))
	t2 = (c2 * m2 * mod_inv(m2, n2))
	c = (t0 + t1 + t2) % (n0 * n1 * n2)

	return int_to_bytes(find_cube_root(c))

def main():
	plaintext = b"Probando el Broadcast attack para RSA"

	ciphertexts = []
	for _ in range(3):
		rsa = RSA(1024)
		ciphertexts.append((rsa.encrypt(plaintext), rsa.n))

	assert rsa_broadcast_attack(ciphertexts) == plaintext

	print("##########################")
	print("Hastad's Broadcast Attack")
	print("##########################")
	print("\n")

	print("El texto a cifrar es: ")
	print(plaintext)
	print("La clave publica a utilizar en uno de los mensajes es ")
	print("n: ", rsa.n)
	print("e: ", rsa.e)
	print("La clave privada a utilizar en uno de los mensajes es ")
	print("n: ", rsa.n)
	print("d: ", rsa.d)
	print("El valor cifrado mediante la clave es: ")
	print(rsa.encrypt(plaintext))
	print("\n")
	rsa.decrypt(rsa.encrypt(plaintext))
	print("El texto desifrado conseguido por el ataque es: ", rsa_broadcast_attack(ciphertexts))
	

if __name__ == '__main__':
	main()