#!/usr/bin/env python

"""
This file transfer example demonstrates a couple of things:
 1) Transferring files using Axolotl to encrypt each block of the transfer
    with a different ephemeral key.
 2) Using a context manager with Axolotl.

The utility will prompt you for the location of the Axolotl key database
and the blocksize. The blocksize must be chosen so that the maximum number
of blocks is <= 255. Security is optimized by a larger number of blocks,
and transfer speed is optimized by a smaller number of blocks. If you
choose incorrectly, the utility will prompt you with a recommendation.

Key databases can be generated using e.g the init_conversation.py utility.

Syntax for receive is: ./transfer.py -r

Syntax for send is: ./transfer.py -s <filename> <target hostname or ip address>

The end of packet (EOP) and end of file (EOF) markers I use are pretty simple,
but unlikely to show up in ciphertext.
"""


from pyaxo import Axolotl
from contextlib import contextmanager
import sys
import socket
import os

try:
    location = raw_input('Database directory (default ~/.bin)? ').strip()
    if location == '': location = '~/.bin'
    location = os.path.expanduser(location)
    if sys.argv[1] == '-s':
        file_name = sys.argv[2]
        host = sys.argv[3]
        size = int(raw_input('File transfer block size? '))
    port = 50000
except IndexError:
    print 'Usage: ' + sys.argv[0] + ' -(s,r) [<filename> <host>]'
    exit()

backlog = 1

@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    yield s
    s.close()

@contextmanager
def axo(my_name, other_name, dbname, dbpassphrase):
    a = Axolotl(my_name, dbname=dbname, dbpassphrase=dbpassphrase)
    a.loadState(my_name, other_name)
    yield a
    a.saveState()

if sys.argv[1] == '-s':
    # open socket and send data
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((host, port))
        with axo('send', 'receive', dbname=location+'/send.db', dbpassphrase='1') as a:
            with open(file_name, 'rb') as f:
                plaintext = f.read()
                plainlength = len(plaintext)
                while plainlength/size > 253:
                    print 'File too large to transfer - increase size parameter'
                    print 'Recommended >= ' + str(plainlength/128) + ' bytes per block'
                    size = int(raw_input('File transfer block size? '))
                plaintext = str(len(file_name)).zfill(2) + file_name + plaintext
                while len(plaintext) > size:
                    msg = plaintext[:size]
                    if msg == '': break
                    plaintext = plaintext[size:]
                    ciphertext = a.encrypt(msg)
                    s.send(ciphertext + 'EOP')
                if len(plaintext) != 0:
                    ciphertext = a.encrypt(plaintext)
                    s.send(ciphertext + 'EOF')

            # receive confirmation
            confirmation = s.recv(1024)
            if a.decrypt(confirmation) == 'Got It!':
                print 'Transfer confirmed!'
            else:
                print 'Transfer not confirmed...'

if sys.argv[1] == '-r':
    # open socket and receive data
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host = ''
        s.bind((host, port))
        s.listen(backlog)
        client, address = s.accept()
        with axo('receive', 'send', dbname=location+'/receive.db', dbpassphrase='1') as a:
            plaintext = ''
            ciphertext = ''
            while True:
                newtext = client.recv(1024)
                ciphertext += newtext
                if ciphertext[-3:] == 'EOF': break
            if ciphertext == '':
                print 'nothing received'
                exit()
            cipherlist = ciphertext.split('EOP')
            for item in cipherlist:
                if item[-3:] == 'EOF':
                    item = item[:-3]
                plaintext += a.decrypt(item)
            filenamelength = int(plaintext[:2])
            file_name = plaintext[2:2+filenamelength]
            with open(file_name, 'wb') as f:
                f.write(plaintext[2+filenamelength:])

            # send confirmation
            reply = a.encrypt('Got It!')
            client.send(reply)

    print file_name + ' received'
