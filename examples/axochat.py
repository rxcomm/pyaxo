#!/usr/bin/env python

import binascii
import socket
import threading
import sys
from contextlib import contextmanager
from pyaxo import Axolotl

HOST = ''
PORT = 50000 # Arbitrary non-privileged port

@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    yield s
    s.close()

@contextmanager
def axo(my_name, other_name, dbname, dbpassphrase):
    a = Axolotl(my_name, dbname=dbname, dbpassphrase=dbpassphrase)
    a.loadState(my_name, other_name)
    yield a
    a.saveState()

def usage():
    print 'Usage: ' + sys.argv[0] + ' -(s,c,g)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    print ' -g: generate a key database for a nick'
    exit()

try:
    mode = sys.argv[1]
except:
    usage()

NICK = raw_input('Enter your nick: ')
OTHER_NICK = raw_input('Enter the nick of the other party: ')

def hilite(text):
    attr = []
    attr.append('32')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), text)

def recvServer():
    while True:
        data = conn.recv(1024)
        if not data: sys.exit()
        with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
            msg = a.decrypt(data)
            sys.stdout.write(hilite(msg) + '\n' + NICK + ':>\n')
            sys.stdout.flush()

def recvClient():
    while True:
        data = s.recv(1024)
        if not data: sys.exit()
        with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
            msg = a.decrypt(data)
            sys.stdout.write(hilite(msg) + '\n' + NICK + ':>\n')
            sys.stdout.flush()

if mode == '-s':
    print 'Waiting for ' + OTHER_NICK + ' to connect...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        t = threading.Thread(target=recvServer)
        t.daemon = True
        t.start()
        while True:
            data = raw_input(NICK+':>\n')
            if not data: sys.exit()
            if data == '.': sys.exit()
            with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                try:
                    conn.send(a.encrypt(NICK+': '+data))
                except socket.error:
                    print 'Disconnected'
                    sys.exit()

elif mode == '-c':
    HOST = raw_input('Enter the server: ')
    print 'Connecting to ' + HOST + '...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        t = threading.Thread(target=recvClient)
        t.daemon = True
        t.start()
        while True:
            data = raw_input(NICK+':>\n')
            if not data: sys.exit()
            if data == '.': sys.exit()
            with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                try:
                    s.send(a.encrypt(NICK+': '+data))
                except socket.error:
                    print 'Disconnected'
                    sys.exit()

elif mode == '-g':
     a = Axolotl(NICK, dbname=OTHER_NICK+'.db')
     a.printKeys()

     ans = raw_input('Do you want to create a new Axolotl database? y/N ').strip()
     if ans == 'y':
         identity = raw_input('What is the identity key for the other party? ').strip()
         ratchet = raw_input('What is the ratchet key for the other party? ').strip()
         handshake = raw_input('What is the handshake key for the other party? ').strip()
         a.initState(OTHER_NICK, binascii.a2b_base64(identity), binascii.a2b_base64(handshake),
                     binascii.a2b_base64(ratchet))
         a.saveState()
         print 'The database for ' + NICK + ' -> ' + OTHER_NICK + ' has been saved.'
     else:
         print 'OK, nothing has been saved...'

else:
    usage()
