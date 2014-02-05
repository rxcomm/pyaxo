#!/usr/bin/env python

from pyaxo import Axolotl
import sys
import os

# start with a fresh database
try:
    os.remove('./name1.db')
    os.remove('./name2.db')
except OSError:
    pass

# unencrypted databases
a = Axolotl('name1', dbname='name1.db', dbpassphrase=None)
b = Axolotl('name2', dbname='name2.db', dbpassphrase=None)

a.initState('name2', b.state['DHIs'], b.handshakePKey, b.state['DHRs'], verify=False)
b.initState('name1', a.state['DHIs'], a.handshakePKey, a.state['DHRs'], verify=False)

a.saveState()
b.saveState()
