#!/usr/bin/env python
"""
This script is used to convert encrypted Axolotl's database files created with
pyaxo < 0.6.0 into files created with pyaxo >= 0.6.0, which replaced GPG by
PyNaCl for encryption.

To convert the databases, add each filename to the `DATABASE_NAMES` list and
run the script. It will prompt for each file's passphrase, decrypt with the
previously used cipher and encrypt with the current one. If the databases share
the same passphrase, the `dbpassphrase` declaration can be moved out of the
loop so that it will be prompted only once.
"""
import gnupg
import sys
from getpass import getpass

from pyaxo import encrypt_symmetric, hash_


DATABASE_NAMES = []


def convert_dbs():
    gpg = gnupg.GPG()
    gpg.encoding = 'utf-8'

    for dbname in DATABASE_NAMES:
        with open(dbname, 'rb') as f:
            dbpassphrase = getpass('Type passphrase for "{}": '.format(dbname))
            sql = gpg.decrypt_file(f, passphrase=dbpassphrase).data

        if sql:
            with open(dbname, 'wb') as f:
                new_crypt_sql = encrypt_symmetric(key=hash_(dbpassphrase),
                                                  plaintext=sql)
                f.write(new_crypt_sql)
        else:
            print 'Bad passphrase!'


if __name__ == '__main__':
    sys.exit(convert_dbs())
