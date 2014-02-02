#!/usr/bin/env python

"""
This program will encrypt or decrypt a file
"""

from pyaxo import Axolotl
import sys

your_name = raw_input('What is your name? ').strip()

# specify dbname with kwarg - default dbname is axolotl.db
# db passphrase will be prompted for - it can be specified here with dbpassprase kwarg
a = Axolotl(your_name, dbname=your_name+'.db')

try:
    if sys.argv[1] == '-e':
        other_name = \
            raw_input("What is the name of the party that you want to encrypt the file to? " ).strip()
        a.loadState(your_name, other_name)
        a.encrypt_file(sys.argv[2])
        print 'The encrypted file is: ' + sys.argv[2] + '.asc'
    else:
        other_name = \
            raw_input("What is the name of the party that you want to decrypt the file from? " ).strip()
        a.loadState(your_name, other_name)
        a.decrypt_file(sys.argv[2])
except IndexError:
    print 'Usage: ' + sys.argv[0] + ' -(e,d) <filename>'
    exit()
except KeyError:
    print 'The conversation ' + your_name + ' -> ' + other_name + \
          ' is not in the database'
    exit()

a.saveState()

