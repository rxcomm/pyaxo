#!/usr/bin/env python

from pyaxo import Axolotl
import sys
import os

# start with a fresh database
try:
    os.remove('./axolotl.db')
except OSError:
    pass

a = Axolotl('name1')
b = Axolotl('name2')

a.initState('name2', b.identityPKey, b.handshakePKey, b.ratchetPKey)
b.initState('name1', a.identityPKey, a.handshakePKey, a.ratchetPKey)

a.saveState()
b.saveState()
