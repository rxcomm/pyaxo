#!/usr/bin/env python

import binascii
import socket
import threading
import sys
import os
import curses
import curses.textpad
from contextlib import contextmanager
from pyaxo import Axolotl
from time import sleep

HOST = ''
PORT = 50000 # Arbitrary non-privileged port

@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    yield s
    s.close()

@contextmanager
def axo(my_name, other_name, dbname, dbpassphrase):
    a = Axolotl(my_name, dbname=dbname, dbpassphrase=dbpassphrase)
    a.loadState(my_name, other_name)
    yield a
    a.saveState()

def windows():
    stdscr = curses.initscr()
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(3, 2, -1)
    curses.cbreak()
    curses.curs_set(1)
    size = stdscr.getmaxyx()
    input_win = curses.newwin(3, size[1]-1, size[0]-4, 0)
    output_win = curses.newwin(size[0]-4, size[1]-1, 0, 0)
    input_win.idlok(1)
    input_win.scrollok(1)
    input_win.nodelay(1)
    output_win.idlok(1)
    output_win.scrollok(1)
    return stdscr, input_win, output_win

def closeWindows():
    curses.nocbreak()
    stdscr.keypad(0)
    curses.echo()
    curses.endwin()

def usage():
    print 'Usage: ' + sys.argv[0] + ' -(s,c,g)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    print ' -g: generate a key database for a nick'
    exit()

def recvServer():
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = conn.recv(1024)
            if not rcv:
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        for data in data_list:
            if data != '':
                with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                    lock.acquire()
                    output_win.addstr(a.decrypt(data), curses.color_pair(3))
                    output_win.refresh()
                    input_win.addstr(0, 0, NICK + ':> ')
                    input_win.refresh()
                    lock.release()

def recvClient():
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = s.recv(1024)
            if not rcv:
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        for data in data_list:
            if data != '':
                with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                    lock.acquire()
                    output_win.addstr(a.decrypt(data), curses.color_pair(3))
                    output_win.refresh()
                    input_win.addstr(0, 0, NICK + ':> ')
                    input_win.refresh()
                    lock.release()

try:
    mode = sys.argv[1]
except:
    usage()

NICK = raw_input('Enter your nick: ')
OTHER_NICK = raw_input('Enter the nick of the other party: ')
lock = threading.Lock()

if mode == '-s':
    print 'Waiting for ' + OTHER_NICK + ' to connect...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        stdscr, input_win, output_win = windows()
        input_win.addstr(0, 0, NICK + ':> ')
        input_win.clrtobot()
        input_win.refresh()
        t = threading.Thread(target=recvServer)
        t.daemon = True
        t.start()
        data = ''
        while True:
            char = -1
            while char != ord('\n'):
                lock.acquire()
                char = input_win.getch()
                lock.release()
                if char >= 0:
                    data += chr(char)
                sleep(0.02)
            if data == '.quit\n':
                closeWindows()
                sys.exit()
            if char == ord('\n'):
                lock.acquire()
                output_win.addstr(NICK+': '+data)
                output_win.refresh()
                input_win.addstr(0, 0, NICK + ':> ')
                input_win.clrtobot()
                input_win.refresh()
                lock.release()
                sleep(0.02)
                with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                    try:
                        conn.send(a.encrypt(NICK+': '+data) + 'EOP')
                        data = ''
                    except socket.error:
                        lock.acquire()
                        input_win.addstr('Disconnected')
                        input_win.refresh()
                        lock.release()
                        closeWindows()
                        sys.exit()

elif mode == '-c':
    HOST = raw_input('Enter the server: ')
    print 'Connecting to ' + HOST + '...'
    with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        stdscr, input_win, output_win = windows()
        input_win.addstr(0, 0, NICK + ':> ')
        input_win.clrtobot()
        input_win.refresh()
        t = threading.Thread(target=recvClient)
        t.daemon = True
        t.start()
        data = ''
        while True:
            char = -1
            while char != ord('\n'):
                lock.acquire()
                char = input_win.getch()
                lock.release()
                if char >= 0:
                    data += chr(char)
                sleep(0.02)
            if data == '.quit\n':
                closeWindows()
                sys.exit()
            if char == ord('\n'):
                lock.acquire()
                output_win.addstr(NICK+': '+data)
                output_win.refresh()
                input_win.addstr(0, 0, NICK + ':> ')
                input_win.clrtobot()
                input_win.refresh()
                lock.release()
                sleep(0.02)
                with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db', dbpassphrase='1') as a:
                    try:
                        s.send(a.encrypt(NICK+': '+data) + 'EOP')
                        data = ''
                    except socket.error:
                        lock.acquire()
                        input_win.addstr('Disconnected')
                        input_win.refresh()
                        lock.release()
                        closeWindows()
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
