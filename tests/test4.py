#!/usr/bin/env python

import os
from pyaxo import Axolotl

# need clean database for this example to work
try:
    os.remove('./axolotl.db')
except OSError:
    pass

# create two instance classes with unencrypted database
a = Axolotl('Angie', dbpassphrase=None)
b = Axolotl('Barb', dbpassphrase=None)

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

