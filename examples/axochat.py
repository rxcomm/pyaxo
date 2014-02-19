#!/usr/bin/env python

import binascii
import socket
import threading
import sys
import curses
from curses.textpad import Textbox
from random import randint
from contextlib import contextmanager
from pyaxo import Axolotl
from time import sleep

"""
Standalone chat script using AES256 encryption with Axolotl ratchet for
key management.

Usage:
1. Create databases using:
     axochat.py -g
   for both nicks in the conversation

2. One side starts the server with:
     axochat.py -s

3. The other side connects the client to the server with:
     axochat.py -c

4. .quit at the chat prompt will quit (don't forget the "dot")

Port 50000 is the default port, but you can choose your own port as well.

Be sure to edit the getPasswd() method to return your password. You can
hard code it or get it from e.g. a keyring. It just has to match the password
you used when creating the database.

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

Copyright (C) 2014 by David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

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

class _Textbox(Textbox):
    """
    curses.textpad.Textbox requires users to ^g on completion, which is sort
    of annoying for an interactive chat client such as this, which typically only
    reuquires an enter. This subclass fixes this problem by signalling completion
    on Enter as well as ^g. Also, map <Backspace> key to ^h.
    """
    def __init__(*args, **kwargs):
        Textbox.__init__(*args, **kwargs)

    def do_command(self, ch):
        if ch == 10: # Enter
            return 0
        if ch == 127: # Enter
            return 8
        return Textbox.do_command(self, ch)

def validator(ch):
    """
    Update screen if necessary and release the lock so receiveThread can run
    """
    global screen_needs_update
    try:
        if screen_needs_update:
            curses.doupdate()
            screen_needs_update = False
        return ch
    finally:
        lock.release()
        sleep(0.01) # let receiveThread in if necessary
        lock.acquire()

def windows():
    stdscr = curses.initscr()
    curses.noecho()
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(3, 2, -1)
    curses.cbreak()
    curses.curs_set(1)
    (sizey, sizex) = stdscr.getmaxyx()
    input_win = curses.newwin(8, sizex, sizey-8, 0)
    output_win = curses.newwin(sizey-8, sizex, 0, 0)
    input_win.idlok(1)
    input_win.scrollok(1)
    input_win.nodelay(1)
    input_win.leaveok(0)
    input_win.timeout(100)
    input_win.attron(curses.color_pair(3))
    output_win.idlok(1)
    output_win.scrollok(1)
    output_win.leaveok(0)
    return stdscr, input_win, output_win

def closeWindows(stdscr):
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

def receiveThread(sock, stdscr, input_win, output_win):
    global screen_needs_update
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = sock.recv(1024)
            if not rcv:
                input_win.move(0, 0)
                input_win.addstr('Disconnected - Ctrl-C to exit!')
                input_win.refresh()
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        lock.acquire()
        (cursory, cursorx) = input_win.getyx()
        for data in data_list:
            if data != '':
                with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db',
                         dbpassphrase=getPasswd(NICK)) as a:
                    output_win.addstr(a.decrypt(data))
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
        sleep(0.01) # write time for axo db
        screen_needs_update = True
        lock.release()

def chatThread(sock):
    global screen_needs_update
    stdscr, input_win, output_win = windows()
    input_win.addstr(0, 0, NICK + ':> ')
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True
    t = threading.Thread(target=receiveThread, args=(sock, stdscr, input_win,output_win))
    t.daemon = True
    t.start()
    try:
        while True:
            lock.acquire()
            data = textpad.edit(validator)
            if NICK+':> .quit' in data:
                closeWindows(stdscr)
                sys.exit()
            input_win.clear()
            input_win.addstr(NICK+':> ')
            output_win.addstr(data.replace('\n', '') + '\n', curses.color_pair(3))
            output_win.noutrefresh()
            input_win.move(0, len(NICK)+3)
            input_win.cursyncup()
            input_win.noutrefresh()
            screen_needs_update = True
            data = data.replace('\n', '') + '\n'
            with axo(NICK, OTHER_NICK, dbname=OTHER_NICK+'.db',
                     dbpassphrase=getPasswd(NICK)) as a:
                try:
                    sock.send(a.encrypt(data) + 'EOP')
                except socket.error:
                    input_win.addstr('Disconnected')
                    input_win.refresh()
                    closeWindows(stdscr)
                    sys.exit()
            sleep(0.01) # write time for axo db
            lock.release()
    except KeyboardInterrupt:
        closeWindows(stdscr)

def getPasswd(nick):
    return '1'

if __name__ == '__main__':
    try:
        mode = sys.argv[1]
    except:
        usage()

    NICK = raw_input('Enter your nick: ')
    OTHER_NICK = raw_input('Enter the nick of the other party: ')
    lock = threading.Lock()
    screen_needs_update = False
    HOST = ''
    while True:
        try:
            if mode == '-g':
                PORT = 50000 # dummy assignment
                break
            PORT = raw_input('TCP port (1 for random choice, 50000 is default): ')
            PORT = int(PORT)
            break
        except ValueError:
            PORT = 50000
            break
    if PORT >= 1025 and PORT <= 65535:
        pass
    elif PORT == 1:
        PORT = 1025 + randint(0, 64510)
        print 'PORT is ' + str(PORT)

    if mode == '-s':
        print 'Waiting for ' + OTHER_NICK + ' to connect...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            chatThread(conn)

    elif mode == '-c':
        HOST = raw_input('Enter the server: ')
        print 'Connecting to ' + HOST + '...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            chatThread(s)

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
