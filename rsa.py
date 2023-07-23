# https://en.wikipedia.org/wiki/RSA_(cryptosystem)
#
#
# Pick 2 prime numbers called p and q
#
# Compute the modulus n = p * q
#
# Compute the totient of n, which can be found by the formula phi(n) = (p - 1) * (q - 1)
#
# Pick a positive integer e that is coprime to the totient (see here for an explanation of coprimes) - this will be the exponent used in the public key
#
# Compute the modular multiplicative inverse of 'e (mod phi(n))' - this will be the exponent d used in the private key
# -https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
#
# To encrypt a number m into a ciphered number c, use the following formula: c = m**e (mod n)
#
# To decrypt a number c back into the original number m, use the following formula: m = c**d (mod n)
# from scipy import constants

from math import gcd


class RSA:
    def __init__(self, p:int, q:int, e:int=None):
        # self.golden = (1 + 5 ** 0.5) / 2
        self.prime_p = p
        self.prime_q = q
        self.modulus = p*q

        # Euleur's Totient phi(n) = (p - 1) * (q - 1)
        self.totient = (p - 1) * (q - 1)
        # public key exponent e = 1 < e < phi(n)
        self.public = self._coprime() if e is None else e
        # private key exponent d = e (mod phi(n))
        self.private = self._modular_multiplicative_inverse()


    def _modular_multiplicative_inverse(self) -> int:
        return pow(self.public, -1, self.totient)


    def _coprime(self) -> int:
        for num in range(max([self.prime_p+1, self.prime_q+1]), self.totient - 1):
            if gcd(num, self.totient) == 1:
                return num


    def encrypt(self, m:int) -> int:
        # c = m**e (mod n)
        c = (m ** self.public) % self.modulus
        return c


    def decrypt(self, c:int):
        # m = c**d (mod n)
        return pow(c, self.private, self.modulus)


rsa = RSA(p=72689, q=99787, e=99791)