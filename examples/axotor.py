#!/usr/bin/env python

import hashlib
import socket
import threading
import sys
import os
import curses
import socks
import stem.process
import wh
from binascii import a2b_base64 as a2b
from binascii import b2a_base64 as b2a
from getpass import getpass
from smp import SMP
from stem.control import Controller
from stem.util import term
from curses.textpad import Textbox
from contextlib import contextmanager
from pyaxo import Axolotl
from time import sleep

"""
Standalone chat script using libsodium for encryption with the Axolotl
ratchet for key management.

This version of the chat client makes connections over the tor network.
The server creates an ephemeral hidden service and the client connects
to the hidden service. You will need to load the following additional
python modules for this to work: stem, pysocks, txtorcon, pysocks,
and magic-wormhole. They are available on pypi via pip.

Axotor also requires tor (>=2.9.1). Currently this is in the unstable
branch. So you may need to update your distribution's tor repository
accordingly.

The only inputs required are the nicks of the conversants, as well as
a master key. The master key must be of the form N-x where N is an
integer (1-3 digits should be fine) and x is a lower-case alphanumeric
string. The initial axolotl database configuration and credential
exchange are derived from the master key. The master key should be
exchanged out-of-band between the two conversants before communication
can be established. An example master key might be 293-xyzzy (don't use
this one).

On start, the program initializes a tor server and exchanges axolotl
and hidden service authentication credentials over tor using PAKE
(password-authenticated key exchange). The specific implementation of
PAKE used is https://github.com/warner/magic-wormhole. The server
side creates an ephemeral hidden service that requires basic_auth
to connect.

The hidden service and axolotl credentials are ephemeral. They exist
only in ram, and will be deleted upon exit from the program. Exit by
typing .quit at the chat prompt.

The client also does an authentication step using the Socialist
Millionaire's Protocol. During startup, after a network connection is
established, you will be prompted for a secret. If the secret
matches that input by the other party, a chat is established and
the input window text appears in green. If the secret does not match
the other party's secret, you will be prompted whether or not to
continue. If you continue, the input window text will appear in red
to remind you that the session is unauthenticated.

The Axolotl protocol is actually authenticated through the key
agreement process when the credentials are created. You may wonder why
the additional SMP authentication step is included. The answer lies in
the fact that between sessions, the key databases are stored on disk
and - at least in principle - could be tampered with. This SMP step
assures that the other party to your session is actually who you think
it is.

Usage:
1. One side starts the server with:
     axotor.py -s

2. The other side connects the client to the server with:
     axotor.py -c

3. .quit at the chat prompt will quit (don't forget the "dot")

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

Copyright (C) 2015-2016 by David R. Andersen <k0rx@RXcomm.net>

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

TOR_SERVER_PORT             = 9054
TOR_SERVER_CONTROL_PORT     = 9055
TOR_CLIENT_PORT             = 9154
TOR_CLIENT_CONTROL_PORT     = 9155
TOR_CONTROL_PASSWORD        = 'axotor'
TOR_CONTROL_HASHED_PASSWORD = \
    '16:0DF8A51D5BB7A97160265FEDD732D47AB07FC143446943D92C2C584673'

@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    yield s
    s.close()

@contextmanager
def torcontext():
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, '127.0.0.1', TOR_CLIENT_PORT)
        yield s
        s.close()
    except socks.SOCKS5Error:
        print ''
        print 'You need to wait long enough for the Hidden Service'
        print 'at the server to be established. Try again in a'
        print 'minute or two.'

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
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
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
    sys.exit()

def receiveThread(sock, stdscr, input_win, output_win, text_color):
    global screen_needs_update, a
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = sock.recv(1024)
            if not rcv:
                input_win.move(0, 0)
                input_win.addstr('Disconnected - Ctrl-C to exit!',
                                 text_color)
                input_win.refresh()
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        lock.acquire()
        (cursory, cursorx) = input_win.getyx()
        for data in data_list:
            if data != '':
                data = a.decrypt(data)
                output_win.addstr(data)
            if OTHER_NICK+':> .quit' in data:
                closeWindows(stdscr)
                print OTHER_NICK+' exited the chat...'
                sleep(1.5)
                os._exit(0)
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
        screen_needs_update = True
        lock.release()

def chatThread(sock, smp_match):
    global screen_needs_update, a
    stdscr, input_win, output_win = windows()
    if smp_match:
        text_color = curses.color_pair(2) # green
    else:
        text_color = curses.color_pair(1) # red
    input_win.attron(text_color)
    input_win.addstr(0, 0, NICK + ':> ')
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True
    t = threading.Thread(target=receiveThread,
                         args=(sock, stdscr, input_win,
                               output_win, text_color))
    t.daemon = True
    t.start()
    try:
        while True:
            lock.acquire()
            data = textpad.edit(validator)
            input_win.clear()
            input_win.addstr(NICK+':> ')
            output_win.addstr(data.replace('\n', '') + '\n', text_color)
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
            if NICK+':> .quit' in data:
                closeWindows(stdscr)
                print 'Notifying '+OTHER_NICK+' that you are quitting...'
                sys.exit()
            lock.release()
    except KeyboardInterrupt:
        closeWindows(stdscr)

def tor(port, controlport, tor_dir, descriptor_cookie):
    tor_process = stem.process.launch_tor_with_config(
        tor_cmd = 'tor',
        config = {
                  'ControlPort': str(controlport),
                  'SocksPort'  : str(port),
                  'Log'        : [ 'NOTICE stdout', 'ERR file /tmp/tor_error_log', ],
                  'DataDirectory' : tor_dir,
                  'HashedControlPassword' : TOR_CONTROL_HASHED_PASSWORD,
                  'HidServAuth': descriptor_cookie,
                 },
        completion_percent = 100,
        take_ownership = True,
        timeout = 90,
        init_msg_handler = print_bootstrap_lines,
        )
    return tor_process

def print_bootstrap_lines(line):
    if 'Bootstrapped ' in line:
        print(term.format(line, term.Color.RED))

def clientController(descriptor_cookie, onion):
    controller = Controller.from_port(address='127.0.0.1',
                                      port=TOR_CLIENT_CONTROL_PORT)
    try:
        controller.authenticate(password=TOR_CONTROL_PASSWORD),
        controller.set_options([
            ('HidServAuth', onion + ' ' + descriptor_cookie),
            ])
    except Exception as e:
        print e
    return controller

def ephemeralHiddenService():
    PORT = 50000
    HOST = '127.0.0.1'
    print 'Waiting for Hidden Service descriptor to be published...'
    print ' (this may take some time)'

    controller = Controller.from_port(address='127.0.0.1',
                                      port=TOR_SERVER_CONTROL_PORT)
    controller.authenticate(password=TOR_CONTROL_PASSWORD)
    try:
        hs = controller.create_ephemeral_hidden_service(PORT,
                                                        basic_auth={'axotor': None},
                                                        await_publication=True)
    except Exception as e:
        print e
    return controller, hs.client_auth['axotor'], hs.service_id +'.onion'

def credentialsSend(mkey, cookie, ratchet_key, onion):
    w = wh.send(unicode(mkey),
                cookie+'___'+ratchet_key+'___'+onion,
                TOR_SERVER_PORT)
    return w

def credentialsReceive(mkey):
    return wh.receive(unicode(mkey), TOR_CLIENT_PORT)

def smptest(secret, sock, is_server):
    global a
    # Create an SMP object with the calculated secret
    smp = SMP(secret)

    if is_server:
        # Do the SMP protocol
        buffer = sock.recv(2435, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = a.decrypt(buffer[:-padlength])
        buffer = smp.step2(buffer)
        buffer = a.encrypt(buffer)
        padlength = 4535-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(3465, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = a.decrypt(buffer[:-padlength])
        buffer = smp.step4(buffer)
        buffer = a.encrypt(buffer)
        padlength = 1365-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

    else:
        # Do the SMP protocol
        buffer = smp.step1()
        buffer = a.encrypt(buffer)
        padlength = 2435-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(4535, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = a.decrypt(buffer[:-padlength])
        buffer = smp.step3(buffer)
        buffer = a.encrypt(buffer)
        padlength = 3465-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(1365, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = a.decrypt(buffer[:-padlength])
        smp.step5(buffer)

    # Check if the secrets match
    if smp.match:
        print 'Secrets Match!'
        sleep(1)
        smp_match = True
    else:
        print 'Secrets DO NOT Match!'
        smp_match = False
    return smp_match

def doSMP(sock, is_server):
    global a
    ans = raw_input('Run SMP authentication step? (y/N)? ')
    if not ans == 'y': ans = 'N'
    sock.send(a.encrypt(ans))
    data = sock.recv(121, socket.MSG_WAITALL)
    data = a.decrypt(data)
    if ans == 'N' and data == 'y':
        print 'Other user requested SMP authentication'
    if ans == 'y' or data == 'y':
        print 'Performing per-session SMP authentication...'
        ans = getpass('Enter SMP secret: ')
        print 'Running SMP protocol...'
        secret = ans + a.state['CONVid']
        smp_match = smptest(secret, sock, is_server)
        if not smp_match:
            ans = raw_input('Continue? (y/N) ')
            if ans != 'y':
                print 'Exiting...'
                sys.exit()
    else:
        print 'OK - skipping SMP step and assuming ' + \
               OTHER_NICK + ' is already authenticated...'
        smp_match = True
        sleep(2)
    return smp_match

if __name__ == '__main__':
    global a
    try:
        mode = sys.argv[1]
    except:
        usage()

    NICK = raw_input('Enter your nick: ')
    OTHER_NICK = raw_input('Enter the nick of the other party: ')
    lock = threading.Lock()
    screen_needs_update = False
    HOST = '127.0.0.1'
    PORT=50000
    mkey = getpass('What is the masterkey (format: NNN-xxxx)? ')

    if mode == '-s':
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        a.createState(other_name=OTHER_NICK,
                           mkey=hashlib.sha256(mkey).digest(),
                           mode=False)
        tor_process = tor(TOR_SERVER_PORT,
                          TOR_SERVER_CONTROL_PORT,
                          '/tmp/tor.server',
                          '')
        hs, cookie, onion = ephemeralHiddenService()
        print 'Exhanging credentials via tor...'
        if credentialsSend(mkey,
                           cookie,
                           b2a(a.state['DHRs']).strip(),
                           onion):
            pass
        else:
            sys.exit(1)
        print 'Credentials sent, waiting for ' + OTHER_NICK + ' to connect...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            print 'Connected...'
            smp_match = doSMP(conn, True)
            chatThread(conn, smp_match)

    elif mode == '-c':
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        tor_process = tor(TOR_CLIENT_PORT,
                          TOR_CLIENT_CONTROL_PORT,
                          '/tmp/tor.client',
                          '')
        print 'Exhanging credentials via tor...'
        creds = credentialsReceive(mkey)
        cookie, rkey, onion = creds.split('___')
        controller = clientController(cookie, onion)
        a.createState(other_name=OTHER_NICK,
                      mkey=hashlib.sha256(mkey).digest(),
                      mode=True,
                      other_ratchetKey=a2b(rkey))

        print 'Credentials received, connecting to ' + OTHER_NICK + '...'
        with torcontext() as s:
            s.connect((onion, PORT))
            print 'Connected...'
            smp_match = doSMP(s, False)
            chatThread(s, smp_match)

    else:
        usage()
