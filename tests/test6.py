#!/usr/bin/env python
"""
Script that tests if two previously created databases can exchange
messages. Make sure that the values for `a_name`, `b_name`, `dbname`
and `dbpassphrase` are correct.
"""
from pyaxo import Axolotl

# create two instance classes with encrypted databases
a_name = 'angie'
b_name = 'barb'
a = Axolotl(a_name,
            dbname=b_name+'.db',
            dbpassphrase=a_name)
b = Axolotl(b_name,
            dbname=a_name+'.db',
            dbpassphrase=b_name)

# load their states
a.loadState(a_name, b_name)
b.loadState(b_name, a_name)

# tell who is who
if a.mode:
    print a_name, 'is Alice-like'
    print b_name, 'is Bob-like'
else:
    print a_name, 'is Bob-like'
    print b_name, 'is Alice-like'

# send some messages back and forth
msg0 = a.encrypt('message 0')
print 'b decrypt: ', b.decrypt(msg0)
msg1 = b.encrypt('message 1')
print 'a decrypt: ', a.decrypt(msg1)
msg2 = a.encrypt('message 2')
msg3 = a.encrypt('message 3')
print 'b decrypt: ', b.decrypt(msg2)
msg4 = b.encrypt('message 4')
print 'a decrypt: ', a.decrypt(msg4)
msg5 = a.encrypt('message 5')
print 'b decrypt: ', b.decrypt(msg5)
print 'b decrypt: ', b.decrypt(msg3)

# save the state
a.saveState()
b.saveState()
