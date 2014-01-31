#!/usr/bin/env python

from pyaxo import Axolotl
import sys

a = Axolotl('name2')
a.loadState('name2', 'name1')

if sys.argv[1] == '-e':
    a.encrypt_file(sys.argv[2])
else:
    a.decrypt_file(sys.argv[2])

a.saveState()

