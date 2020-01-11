from random import randint
from Crypto import Random
from Crypto.Util.number import getPrime, getStrongPrime
import sys

def maingraphicview(n, dosB, tresB):
    print("Representación en escala de 100 respecto a 0 y N")
    print("El rango de valores es: ", (n-0))
    sys.stdout.write("[0")
    dosB_intervalo = (dosB * 100) // n
    tresB_intervalo = (tresB * 100) // n
    for i in range(100):
        if i == dosB_intervalo and i == tresB_intervalo:
            sys.stdout.write("U")
        elif i == dosB_intervalo:
            sys.stdout.write("2B")
        elif i == tresB_intervalo:
            sys.stdout.write("3B")
        else:
            sys.stdout.write("-")
    #sys.stdout.write(str(n))
    sys.stdout.write("]")
    print("")

def graphicview(limiteMenor, limiteMayor, M):
    
    if len(M) == 1:
        min = M[0][0]
        max = M[0][1]
        print("El rango de valores es: ", (limiteMayor-limiteMenor))
        print("Rango anterior:", limiteMenor, " ", limiteMayor )
        print("Rango nuevo:   ", min, " ", max)
        sys.stdout.write("[")
        min_intervalo = ((min - limiteMenor) * 100) // (limiteMayor - limiteMenor)
        max_intervalo = ((max - limiteMenor) * 100) // (limiteMayor - limiteMenor)
        for i in range(100):
            if i == min_intervalo and i == max_intervalo and min == max:
                sys.stdout.write("U")
            elif i == min_intervalo:
                sys.stdout.write("m")
            elif i == max_intervalo:
                sys.stdout.write("M")
            else:
                sys.stdout.write("-")
        #sys.stdout.write(str(tresB))
        sys.stdout.write("]")
        print("")
        print("")
    else:
        print("Mas de un intervalo")

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

def gcd(a, b):
    """Computes the greatest common divisor between a and b using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b

    return a


def lcm(a, b):
    """Computes the lowest common multiple between a and b using the GCD method."""
    return a // gcd(a, b) * b

class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        """In this exercise, e is fixed to 3 so we will have to find p and q that fit the requirements."""
        self.e = 65537
        phi = 0

        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self._d = mod_inv(self.e, phi)


    def encrypt(self, binary_data):
        """Converts the input bytes to an int (bytes -> int) and then encrypts the int with RSA."""
        int_data = int.from_bytes(binary_data, byteorder='big')
        print("El valor en decimal, del mensaje a cifrar es:" , int_data)
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        """Decrypts the encrypted input data to an int and then converts it back to bytes (int -> bytes)."""
        int_data = pow(encrypted_int_data, self._d, self.n)
        return int_to_bytes(int_data)

def int_to_bytes(n):
    """Converts the given int n to bytes and returns them."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

#computes the smallest integer greater than or equal to a/b
def ceil(a, b):
    return (a + b - 1) // b


class RSAPaddingOracle(RSA):


    def is_padding_correct(self, encrypted_int_data):

        plaintext = self.decrypt(encrypted_int_data)
        return len(plaintext) == ceil(self.n.bit_length(), 8) and plaintext[:2] == b'\x00\x02'

    def decrypt(self, encrypted_int_data):
        return b'\x00' + super(RSAPaddingOracle, self).decrypt(encrypted_int_data)


def append_and_merge(intervals, lower_bound, upper_bound):

    for i, (a, b) in enumerate(intervals):

        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            intervals[i] = new_a, new_b
            return

    intervals.append((lower_bound, upper_bound))


def pkcs_1_5_padding_oracle_attack(ciphertext, rsa_padding_oracle, key_byte_length, c_is_pkcs_conforming=True):
    """Implements the PKCS 1.5 padding oracle attack described by Bleichenbacher in CRYPTO '98."""

    B = 2 ** (8 * (key_byte_length - 2))
    n, e = rsa_padding_oracle.n, rsa_padding_oracle.e

    print("El valor de n es ", n)
    print("El valor de e es ", e)
    print("El valor de B es ", B)
    maingraphicview(n, 2*B, 3*B)
    # Set the starting values
    c_0 = ciphertext
    M = [(2 * B, 3 * B - 1)]
    i = 1

    # Si c aún no cumple con PKCS 1.5, realizamos un paso adicional
    if not c_is_pkcs_conforming:

        # Step 1: Blinding
        #No suele ser utilizado ya que el c que capturamos, su m, se supone que cumple con PKCS
        while True:
            s = randint(0, n - 1)
            c_0 = (ciphertext * pow(s, e, n)) % n
            if rsa_padding_oracle.is_padding_correct(c_0):
                break

    while True:
        # Step 2.a: Starting the search
        if i == 1:
            s = ceil(n, 3 * B)
            while True:
                s_1 = pow(s, e, n)
                c = (c_0 * s_1) % n
                if rsa_padding_oracle.is_padding_correct(c):
                    #print("El valor de m' es ", s)
                    break
                s += 1

        # Step 2.b: Searching with more than one interval left
        elif len(M) >= 2:
            while True:
                s += 1
                s_1 = pow(s, e, n)
                c = (c_0 * s_1) % n
                if rsa_padding_oracle.is_padding_correct(c):
                    #print("El valor de m' es ", s)
                    break

        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]

            # Verificamos si el intervalo contiene la solución
            if a == b:

                # Si lo hace, la devolvemos como bytes
                return b'\x00' + int_to_bytes(a)

            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)

            while True:
                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.is_padding_correct(c):
                    #print("El valor de m' es ", s)
                    break
                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []

        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n

            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)

                if l > u:
                    raise Exception('Error inesperado: l > u en el paso 3')

                append_and_merge(M_new, l, u)

        if len(M_new) == 0:
            raise Exception('Error inesperado: Hay 0 intervalos.')

        graphicview(M[0][0], M[0][1], M_new)
        M = M_new
        i += 1


def pkcs_1_5_pad(binary_data, key_byte_length):
    """Pads the given binary data conforming to the PKCS 1.5 format."""
    padding_string = Random.new().read(key_byte_length - 3 - len(binary_data))
    return b'\x00\x02' + padding_string + b'\x00' + binary_data


def main():
    key_bit_length = 256
    key_byte_length = ceil(key_bit_length, 8)

    print("##########################")
    print("Bleichenbacher Attack")
    print("##########################")
    print("\n")

    print("Tamaño de la clave en bytes: ",  key_byte_length)

    rsa_padding_oracle = RSAPaddingOracle(key_bit_length)

    # Pad a short message m and encrypt it to get c
    data_block = b'a'
    m = pkcs_1_5_pad(data_block, key_byte_length)

    print("El mensaje a cifrar es: ", data_block)
    print("El mensaje con el rellono es: ", m)

    c = rsa_padding_oracle.encrypt(m)

    print("El mensaje cifrado, es(en decimal): ", c)

    mensaje_oracle = pkcs_1_5_padding_oracle_attack(c, rsa_padding_oracle, key_byte_length)
    print("El mensaje elaborado mediante el oraculo es: ", mensaje_oracle)
    assert m == mensaje_oracle


if __name__ == '__main__':
    main()