#!/usr/bin/env python

import os
from pyaxo import Axolotl

# need clean database for this example to work
try:
    os.remove('./axolotl.db')
except OSError:
    pass

# create two instance classes with database passphrase specified as kwarg
a = Axolotl('Angie', dbpassphrase='123')
b = Axolotl('Barb', dbpassphrase='123')

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

# send some messages back and forth
msg0 = a.encrypt('message 0')
msg1 = a.encrypt('message 1')
msg2 = a.encrypt('message 2')
msg3 = a.encrypt('message 3')
msg4 = a.encrypt('message 4')
msg5 = a.encrypt('message 5')
msg6 = a.encrypt('message 6')
msg7 = a.encrypt('message 7')
msg8 = a.encrypt('message 8')
msg9 = a.encrypt('message 9')
msg10 = a.encrypt('message 10')
msg11 = a.encrypt('message 11')
print 'b decrypt: ', b.decrypt(msg11)
print 'b decrypt: ', b.decrypt(msg10)
print 'b decrypt: ', b.decrypt(msg9)
print 'b decrypt: ', b.decrypt(msg8)
print 'b decrypt: ', b.decrypt(msg7)
print 'b decrypt: ', b.decrypt(msg6)
print 'b decrypt: ', b.decrypt(msg5)
print 'b decrypt: ', b.decrypt(msg4)
print 'b decrypt: ', b.decrypt(msg3)
print 'b decrypt: ', b.decrypt(msg2)
print 'b decrypt: ', b.decrypt(msg1)
print 'b decrypt: ', b.decrypt(msg0)

msg0 = b.encrypt('message 0')
msg1 = b.encrypt('message 1')
msg2 = b.encrypt('message 2')
msg3 = b.encrypt('message 3')
msg4 = b.encrypt('message 4')
msg5 = b.encrypt('message 5')
msg6 = b.encrypt('message 6')
msg7 = b.encrypt('message 7')
msg8 = b.encrypt('message 8')
msg9 = b.encrypt('message 9')
msg10 = b.encrypt('message 10')
msg11 = b.encrypt('message 11')
print 'a decrypt: ', a.decrypt(msg11)
print 'a decrypt: ', a.decrypt(msg10)
print 'a decrypt: ', a.decrypt(msg9)
print 'a decrypt: ', a.decrypt(msg8)
print 'a decrypt: ', a.decrypt(msg7)
print 'a decrypt: ', a.decrypt(msg6)
print 'a decrypt: ', a.decrypt(msg5)
print 'a decrypt: ', a.decrypt(msg4)
print 'a decrypt: ', a.decrypt(msg3)
print 'a decrypt: ', a.decrypt(msg2)
print 'a decrypt: ', a.decrypt(msg1)
print 'a decrypt: ', a.decrypt(msg0)
# save the state
a.saveState()
b.saveState()

