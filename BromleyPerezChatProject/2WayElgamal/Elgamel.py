#
# * Elgamel.py; an implementation of elgamal.
#
# * This program is meant to be a helper program for the encryption/decryption for client
# * and server. This implements almost the entire elgamel structure, outside of
# * half mask and multiplier calculations.
#
#
# * Project Prep #2
# * @author Caden Bromley, Chris Perez
# * @email bromlecl205@potsdam.edu, perezcm205@potsdam.edu
# * @due 22 November 2025
# * @course CIS 475
#

import sys
import random
import secrets

#
# * _prime_Check; Checks if the potential number generated from generatePrime is a prime. [SAME CODE FROM RSA ASSIGNMENT]
#
# * This prime checking is not deterministic, it is probabilistic. It uses the Miller-Rabin algorithm, essentially
# * built off of fermats theorem. D starts as the num - 1, and divides until it is not even anymore. Each division is
# * added and turned into S. For a total of 10 times, to ensure that the number is a prime number, the algorithm loops
# * by testing the fermat theorem of a^d mod num. If it passes, it continues. If it doesn't pass, it will do
# * additional checks by squaring the  a^d mod num value s - 1 times, while doing modulo num. If it fails here, then
# * it is likely not a prime. If it passes, then it is likely a prime.
#
# * @param num; candidate to be a prime.
# * @return; if it is a prime or not
def _prime_Check(num):
  k = 10
  d = num - 1
  s = 0
  result = 0
  while d % 2 == 0:
    d = d // 2
    s = s + 1
  for i in range(k):
    a = random.randint(2, num - 2)
    check = pow(a, d, num)
    if (check == 1 or check == num - 1):
      continue
    else:
      for j in range (s - 1):
        check = pow(check, 2, num)
        if check == num - 1:
          break
      if check != num - 1:
        return False
  return True


#
# *_generate_Prime; creates a prime based off of bits
#
# * This program takes in bits as a parameter and generates those primes based on the number of bits
# * given by the user. We want to create safe primes for creating generators, so it creates a number
# * and then multiplies it by two and adds 1. It only returns if both of those are prime numbers.
#
# * @param bits; number of bits for prime
# * @return; the primes (safe prime and normal)
def _generate_Prime(bits):
    while True:
        potential = random.getrandbits(bits) | (1 << bits - 1) | 1
        if _prime_Check((potential * 2) + 1) and _prime_Check(potential):
            return potential * 2 + 1, potential


#
# * _make_Generator; creates a generator using the generator logic
#
# * This assumes that the primes being used are safe primes. This makes the formula
# * much easier and generates a prime using the math logic of a generator. Returns the
# * first that is found
#
# * @param prime; the 2q + 1 prime
# * @param q; a prime
# * @return; the first generator value
def _make_Generator(prime, q):
    for i in range(prime // 2, prime):
        if pow(i, 1, prime) != 1 and pow(i, 2, prime) != 1 and pow(i, q, prime) != 1:
            return i

#
# * getPandG; generates an elgamal prime and generator
#
# * Simply calls helper methods to generate them and returns them
#
# * @param bits; the amount of bits of the prime to be generated
# * @return; the prime and generator
def getPandG(bits):
    p, q = _generate_Prime(bits)
    g = _make_Generator(p, q)
    return p, g


#
# * encrypt(); encrypts an integer message using elgamal
#
# * This computes the full mask here, so the client does not have to do it.
#
# * @param message; integer to be encrypted
# * @param half; halfmask
# * @param power; the k multiplier
# * @param prime; the main prime that is the basis of elgamal
# * @return encrypted integer
def encrypt(message, half, power, prime):
    return (message * pow(half, power, prime)) % prime

#
# * encrypt(); decrypts an integer message using elgamal
#
# * This computes the full mask here (and inverse), so the client does not have to do it.
#
# * @param cipher; integer to be decrypted
# * @param half; halfmask
# * @param power; the k multiplier
# * @param prime; the main prime that is the basis of elgamal
# * @return decrypted integer
def decrypt(cipher, half, power, prime):
    full = pow(half, power, prime)
    fullinverse = pow(full, -1, prime)

    return ((fullinverse * cipher) % prime)
