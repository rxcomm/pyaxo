#!/usr/bin/env python

from pyaxo import Axolotl
import sys

a = Axolotl('name1')
a.loadState('name1', 'name2')

if sys.argv[1] == '-e':
    a.encrypt_file(sys.argv[2])
else:
    a.decrypt_file(sys.argv[2])

a.saveState()

