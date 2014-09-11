#!/usr/bin/env python

"""
A three-toed Axolotl track ;-)
"""


from pyaxo import Axolotl

# create two instance classes
a = Axolotl('Angie')
b = Axolotl('Barb')

# initialize their states
a.initState('Barb', b.state['DHIs'], b.handshakePKey, b.state['DHRs'], verify=False)
b.initState('Angie', a.state['DHIs'], a.handshakePKey, a.state['DHRs'], verify=False)

# tell who is who
if a.mode:
    print 'Angie is Alice-like'
    print 'Barb is Bob-like'
else:
    print 'Angie is Bob-like'
    print 'Barb is Alice-like'

# Walk the three-toed Axolotl walk..
msg0 = a.encrypt('Step 1, Toe 1')
msg1 = a.encrypt('Step 1, Toe 2')
msg2 = a.encrypt('Step 1, Toe 3')
print 'b decrypt: ', b.decrypt(msg0)
print 'b decrypt: ', b.decrypt(msg1)
print 'b decrypt: ', b.decrypt(msg2)
msg0 = b.encrypt('Step 2, Toe 1')
msg1 = b.encrypt('Step 2, Toe 2')
msg2 = b.encrypt('Step 2, Toe 3')
print 'a decrypt: ', a.decrypt(msg0)
print 'a decrypt: ', a.decrypt(msg1)
print 'a decrypt: ', a.decrypt(msg2)
msg0 = a.encrypt('Step 3, Toe 1')
msg1 = a.encrypt('Step 3, Toe 2')
msg2 = a.encrypt('Step 3, Toe 3')
print 'b decrypt: ', b.decrypt(msg0)
print 'b decrypt: ', b.decrypt(msg1)
print 'b decrypt: ', b.decrypt(msg2)
msg0 = b.encrypt('Step 4, Toe 1')
msg1 = b.encrypt('Step 4, Toe 2')
msg2 = b.encrypt('Step 4, Toe 3')
print 'a decrypt: ', a.decrypt(msg0)
print 'a decrypt: ', a.decrypt(msg1)
print 'a decrypt: ', a.decrypt(msg2)
msg0 = a.encrypt('Step 5, Toe 1')
msg1 = a.encrypt('Step 5, Toe 2')
msg2 = a.encrypt('Step 5, Toe 3')
print 'b decrypt: ', b.decrypt(msg0)
print 'b decrypt: ', b.decrypt(msg1)
print 'b decrypt: ', b.decrypt(msg2)
msg0 = b.encrypt('Step 6, Toe 1')
msg1 = b.encrypt('Step 6, Toe 2')
msg2 = b.encrypt('Step 6, Toe 3')
print 'a decrypt: ', a.decrypt(msg0)
print 'a decrypt: ', a.decrypt(msg1)
print 'a decrypt: ', a.decrypt(msg2)
print
print 'You get the idea...'

