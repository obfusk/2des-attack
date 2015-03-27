#!/usr/bin/python

from __future__ import print_function

import random
import sys

from attack2des import encrypt, nth_key, tell, to_bin, to_hex

keylen  = int(sys.argv[1]) if len(sys.argv) > 1 \
                           else attack2des.DEFAULT_KEYLEN
k1      = nth_key(random.randint(0, 2**keylen-1))
k2      = nth_key(random.randint(0, 2**keylen-1))
plains  = [
  "0" * 10 + to_hex("foo"),
  "0" * 10 + to_hex("bar"),
  "0" * 10 + to_hex("baz")
]

tell("> k1      = {}\n> k2      = {}".format(k1, k2))

for plain in plains:
  cipher1 = encrypt(to_bin(k1), to_bin(plain))
  cipher2 = encrypt(to_bin(k2), cipher1)
  tell("> plain   = {}\n> cipher1 = {}\n> cipher2 = {}" \
         .format(plain, to_hex(cipher1), to_hex(cipher2)))
  print(plain); print(to_hex(cipher2))
