#!/usr/bin/env python

from pyaxo import Axolotl

# create two instance classes
a = Axolotl('Alice')
b = Axolotl('Bob')

# initialize their states
a.initState('Bob', b.identityPKey, b.handshakePKey, b.ratchetPKey)
b.initState('Alice', a.identityPKey, a.handshakePKey, a.ratchetPKey)

# tell who is who
if a.mode:
    print 'a = Alice'
    print 'b = Bob'
else:
    print 'a = Bob'
    print 'b = Alice'

# send some messages back and forth
msg0 = a.encrypt('message 0')
msg1 = a.encrypt('message 1')
msg2 = b.encrypt('message 2')
print 'b decrypt: ', b.decrypt(msg0)
print 'b decrypt: ', b.decrypt(msg1)
print 'a decrypt: ', a.decrypt(msg2)
msg3 = a.encrypt('message 3')
msg4 = a.encrypt('message 4')
msg5 = b.encrypt('message 5')
msg6 = a.encrypt('message 6')
msg7 = b.encrypt('message 7')
msg8 = a.encrypt('message 8')
msg9 = a.encrypt('message 9')
msg10 = a.encrypt('message 10')
msg11 = a.encrypt('message 11')
print 'b decrypt: ', b.decrypt(msg11)
print 'b decrypt: ', b.decrypt(msg3)
print 'b decrypt: ', b.decrypt(msg9)
print 'a decrypt: ', a.decrypt(msg5)
print 'a decrypt: ', a.decrypt(msg7)
print 'b decrypt: ', b.decrypt(msg4)
msg12 = b.encrypt('message 12')
print 'a decrypt: ', a.decrypt(msg12)
msg13 = a.encrypt('message 13')
print 'b decrypt: ', b.decrypt(msg13)
print 'b decrypt: ', b.decrypt(msg6)

# save the state
a.saveState()
b.saveState()

