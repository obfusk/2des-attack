#!/usr/bin/python

from __future__ import print_function

import binascii
import Crypto.Cipher.DES
import itertools
import sys
import time

# NB:
# * hex keys are 64-bit hex-encoded ascii strings w/ parity bits
# * bin keys are unhexlified hex keys

DEFAULT_KEYLEN = 24

def tell(x):
  """tell user on stderr"""
  print(x, file = sys.stderr)

def to_bin(x):
  """hex to bin"""
  return binascii.unhexlify(x)

def to_hex(x):
  """bin to hex"""
  return binascii.hexlify(x)

def hamming_weight(n):
  """hamming weight"""
  return len([b for b in bin(n)[2:] if b == '1'])

def add_parity(n):
  """add parity bit"""
  return n << 1 | (1 if hamming_weight(n) % 2 == 0 else 0)

def decrypt(bin_k, bin_cipher):
  """decrypt w/ DES"""
  return Crypto.Cipher.DES.new(bin_k).decrypt(bin_cipher)

def encrypt(bin_k, bin_plain):
  """encrypt w/ DES"""
  return Crypto.Cipher.DES.new(bin_k).encrypt(bin_plain)

def nth_key(n):
  """nth hex key"""
  return "".join([
    "{:02x}".format(add_parity((n >> i * 7) & (2**7-1)))
      for i in reversed(range(8))
  ])

def make_table(plain, keylen = DEFAULT_KEYLEN):
  """create lookup table from bin ciphertext to bin key(s)"""
  table = {}
  for k in itertools.imap(nth_key, xrange(2**keylen)):
    bin_k = to_bin(k); bin_cipher = encrypt(bin_k, to_bin(plain))
    table.setdefault(bin_cipher, []).append(bin_k)
  return table

def decryptions(cipher, keylen = DEFAULT_KEYLEN):
  """iterate over all possible (bin key, bin plain) decryptions"""
  for k in itertools.imap(nth_key, xrange(2**keylen)):
    bin_k = to_bin(k); bin_plain = decrypt(bin_k, to_bin(cipher))
    yield (bin_k, bin_plain)

def find_keypairs(plain, cipher, table, keylen = DEFAULT_KEYLEN):
  """iterate over all found key pairs"""
  for (bin_k2, bin_c1) in decryptions(cipher, keylen):
    k2 = to_hex(bin_k2)
    for bin_k1 in table.get(bin_c1, []):
      k1 = to_hex(bin_k1)
      yield (k1, k2)

def break_2des(plain, cipher, keylen = DEFAULT_KEYLEN):
  """break 2des w/ meet-in-the middle attack"""
  tell("< plain   = {}\n< cipher  = {}".format(plain, cipher))
  t1 = int(time.time())
  table = make_table(plain, keylen)
  t2 = int(time.time())
  tell("< creating table took {:d} seconds".format(t2 - t1))
  t1 = int(time.time())
  keypairs = list(find_keypairs(plain, cipher, table, keylen))
  t2 = int(time.time())
  tell("< finding pairs  took {:d} seconds".format(t2 - t1))
  return keypairs

if __name__ == "__main__":
  keylen  = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_KEYLEN
  lines   = iter(line.rstrip("\n").lower() for line in sys.stdin)
  for (plain, cipher) in itertools.izip(*[lines]*2):
    for (k1, k2) in break_2des(plain, cipher, keylen):
      tell("< k1      = {}\n< k2      = {}".format(k1, k2))
      print(k1, k2)
