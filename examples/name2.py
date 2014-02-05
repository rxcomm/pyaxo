#!/usr/bin/env python

from pyaxo import Axolotl
import sys

a = Axolotl('name2', dbname='name2.db', dbpassphrase=None)
a.loadState('name2', 'name1')

if sys.argv[1] == '-e':
    a.encrypt_file(sys.argv[2])
    print 'Encrypted file is ' + sys.argv[2] +'.asc'
else:
    a.decrypt_file(sys.argv[2])

a.saveState()

