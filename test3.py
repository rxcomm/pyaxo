#!/usr/bin/env python

import binascii
from pyaxo import Axolotl

# create two instance classes
a = Axolotl('Alice')
b = Axolotl('Bob')

# load states
a.loadState('Alice', 'Bob')
b.loadState('Bob', 'Alice')

# tell who is who
if a.mode:
    print 'a = Alice'
    print 'b = Bob'
else:
    print 'a = Bob'
    print 'b = Alice'


with open('file.txt', 'r') as f:
    msg = f.read()

ciphertext = a.encrypt(msg)
s = binascii.b2a_base64(ciphertext)

lines = [s[i:i+64] for i in xrange(0, len(s), 64)]
for line in lines:
    print line

print b.decrypt(ciphertext)
