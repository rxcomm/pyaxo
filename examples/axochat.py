#!/usr/bin/env python

import hashlib
import socket
import threading
import sys
import curses
from curses.textpad import Textbox
from random import randint
from contextlib import contextmanager
from pyaxo import Axolotl
from time import sleep
from getpass import getpass
from binascii import a2b_base64 as a2b
from binascii import b2a_base64 as b2a

"""
Standalone chat script using libsodium for encryption with the Axolotl
ratchet for key management.

Usage:
1. One side starts the server with:
     axochat.py -s

2. The other side connects the client to the server with:
     axochat.py -c

3. Both sides need to input the same master key. This can be any
   alphanumeric string. Also, the server will generate a handshake
   key that is a required input for the client.

4. .quit at the chat prompt will quit (don't forget the "dot")

Port 50000 is the default port, but you can choose your own port as well.

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

Copyright (C) 2014-2016 by David R. Andersen <k0rx@RXcomm.net>

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
    print 'Usage: ' + sys.argv[0] + ' -(s,c)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    exit()

def receiveThread(sock, stdscr, input_win, output_win):
    global screen_needs_update, a
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
                output_win.addstr(a.decrypt(data))
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
        sleep(0.01) # write time for axo db
        screen_needs_update = True
        lock.release()

def chatThread(sock):
    global screen_needs_update, a
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
    global a
    try:
        mode = sys.argv[1]
    except:
        usage()

    NICK = raw_input('Enter your nick: ')
    OTHER_NICK = raw_input('Enter the nick of the other party: ')
    mkey = getpass('Enter the master key: ')
    lock = threading.Lock()
    screen_needs_update = False
    HOST = ''
    while True:
        try:
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
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        a.createState(other_name=OTHER_NICK,
                      mkey=hashlib.sha256(mkey).digest(),
                      mode=False)
        print 'Your ratchet key is: %s' % b2a(a.state['DHRs']).strip()
        print 'Send this to %s...' % OTHER_NICK

        print 'Waiting for ' + OTHER_NICK + ' to connect...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            chatThread(conn)

    elif mode == '-c':
        rkey = raw_input('Enter %s\'s ratchet key: ' % OTHER_NICK)
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        a.createState(other_name=OTHER_NICK,
                      mkey=hashlib.sha256(mkey).digest(),
                      mode=True,
                      other_ratchetKey=a2b(rkey))

        HOST = raw_input('Enter the server: ')
        print 'Connecting to ' + HOST + '...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            chatThread(s)

    else:
        usage()
