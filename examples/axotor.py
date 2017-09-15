#!/usr/bin/env python

import socket
import threading
import sys
import os
import curses
import socks
import stem.process
from wh import WHMgr
import random
from binascii import a2b_base64 as a2b
from binascii import b2a_base64 as b2a
from getpass import getpass
from smp import SMP
from stem.control import Controller
from stem.util import term
from curses.textpad import Textbox
from contextlib import contextmanager
from pyaxo import Axolotl, hash_
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
the additional SMP authentication step is included. This SMP step
is another way to assure you that the other party to your session is
actually who you think it is.

In axotor.py, no database or key is ever stored to disk.

Usage:
1. One side starts the server with:
     axotor.py -s

2. The other side connects the client to the server with:
     axotor.py -c

3. .quit at the chat prompt will quit (don't forget the "dot")

4. .send <filename> will send a file to the other party. The file
   can be from anywhere in the filesystem on the sending computer
   (~/a/b/<filename> supported) and will be stored in the receiver's
   local directory.

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

Copyright (C) 2015-2017 by David R. Andersen <k0rx@RXcomm.net>

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
CLIENT_FILE_TX_PORT         = 2000
SERVER_FILE_TX_PORT         = 2001

# An attempt to limit the damage from this bug in curses:
# https://bugs.python.org/issue13051
# The input textbox is 8 rows high. So assuming a maximum
# terminal width of 512 columns, we arrive at 8x512=4096.
# Most terminal windows should be smaller than this.
sys.setrecursionlimit(4096)

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
        if ch == curses.KEY_RESIZE:
            resizeWindows()
            for i in range(8): # delete 8 input window lines
                Textbox.do_command(self, 1)
                Textbox.do_command(self, 11)
                Textbox.do_command(self, 16)
            return Textbox.do_command(self, 7)
        if ch == 10: # Enter
            return 0
        if ch == 127: # Backspace
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
        winlock.release()
        sleep(0.01) # let receiveThread in if necessary
        winlock.acquire()

def windowFactory():
    stdscr = curses.initscr()
    curses.noecho()
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
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

def resizeWindows():
    global stdscr, input_win, output_win, textpad, text_color
    temp_win = output_win
    yold, xold = output_win.getmaxyx()
    stdscr, input_win, output_win = windowFactory()
    stdscr.noutrefresh()
    ynew, xnew = output_win.getmaxyx()
    if yold > ynew:
        sminrow = yold - ynew
        dminrow = 0
    else:
        sminrow = 0
        dminrow = ynew - yold
    temp_win.overwrite(output_win, sminrow, 0, dminrow, 0, ynew-1, xnew-1)
    del temp_win
    output_win.move(ynew-1, 0)
    output_win.noutrefresh()
    input_win.attron(text_color)
    input_win.noutrefresh()
    curses.doupdate()
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True

def usage():
    print 'Usage: ' + sys.argv[0] + ' -(s,c)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    print 'quit with .quit'
    print 'send file with .send <filename>'
    sys.exit(1)

def reportTransferSocketError():
    global output_win
    with winlock:
        output_win.addstr('Socket error: Something went wrong.\n',
                           curses.color_pair(1))
        output_win.refresh()
    sys.exit()

def sendFile(s, filename, abort):
    global axolotl, output_win
    if abort:
        with cryptlock:
            data = axolotl.encrypt('ABORT') + 'EOP'
        s.send(data)
        try:
            s.recv(3, socket.MSG_WAITALL)
        except socket.error:
            pass
        sys.exit()
    else:
        with winlock:
            output_win.addstr('Sending file %s...\n' % filename,
                               curses.color_pair(3))
            output_win.refresh()
    with open(filename, 'rb') as f:
        data = f.read()
        if len(data) == 0:
            data = 'Sender tried to send a null file!'
        with cryptlock:
            data = axolotl.encrypt(data)
        s.send(data + 'EOP')
    try:
        s.recv(3, socket.MSG_WAITALL)
    except socket.error:
        pass

def receiveFile(s, filename):
    global axolotl, output_win
    data = ''
    while data[-3:] != 'EOP':
        rcv = s.recv(4096)
        data = data + rcv
        if not rcv:
            with winlock:
                output_win.addstr('Receiving %s aborted...\n' % filename,
                                   curses.color_pair(1))
                output_win.refresh()
            try:
                s.send('EOP')
            except socket.error:
                pass
            sys.exit()
    with cryptlock:
        data = axolotl.decrypt(data[:-3])
    if data == 'ABORT':
        with winlock:
            output_win.addstr('Receiving %s aborted...\n' % filename,
                               curses.color_pair(1))
            output_win.refresh()
        sys.exit()
    with open(filename, 'wb') as f:
        f.write(data)
    try:
        s.send('EOP')
    except socket.error:
        pass

def uploadThread(onion, command):
    global output_win
    with transferlock:
        filename = command.split(':> .send ')[1].strip()
        filename = os.path.expanduser(filename)
        if not os.path.exists(filename) or os.path.isdir(filename):
            with winlock:
                output_win.addstr('File %s does not exist...\n' % filename,
                                   curses.color_pair(1))
                output_win.refresh()
            abort = True
        else:
            abort = False
        if onion is None:
            with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(('localhost', SERVER_FILE_TX_PORT))
                    s.listen(1)
                    conn, addr = s.accept()
                except socket.error:
                    reportTransferSocketError()
                sendFile(conn, filename, abort)
        else:
            with torcontext() as s:
                try:
                    s.connect((onion, CLIENT_FILE_TX_PORT))
                except socket.error:
                    reportTransferSocketError()
                sendFile(s, filename, abort)
        with winlock:
            output_win.addstr('%s sent...\n' % filename, curses.color_pair(3))
            output_win.refresh()

def downloadThread(onion, command):
    global output_win
    with transferlock:
        filename = command.split(':> .send ')[1].strip().split('/').pop()
        with winlock:
            output_win.addstr('Receiving file %s...\n' % filename,
                               curses.color_pair(3))
            output_win.refresh()
        if onion is None:
            with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(('localhost', CLIENT_FILE_TX_PORT))
                    s.listen(1)
                    conn, addr = s.accept()
                except socket.error:
                    reportTransferSocketError()
                receiveFile(conn, filename)
        else:
            with torcontext() as s:
                try:
                    s.connect((onion, SERVER_FILE_TX_PORT))
                except socket.error:
                    reportTransferSocketError()
                receiveFile(s, filename)
        with winlock:
           output_win.addstr('%s received...\n' % filename, curses.color_pair(3))
           output_win.refresh()

def receiveThread(sock, text_color, onion):
    global screen_needs_update, a, stdscr, input_win, output_win
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
        with winlock:
            (cursory, cursorx) = input_win.getyx()
            for data in data_list:
                if data != '':
                    with cryptlock:
                        data = axolotl.decrypt(data)
                if ':> .quit' in data:
                    closeWindows(stdscr)
                    print 'The other party exited the chat...'
                    sleep(1.5)
                    os._exit(0)
                if ':> .send ' in data:
                    t = threading.Thread(target=downloadThread,
                                         args=(onion,data))
                    t.start()
                    data = ''
                output_win.addstr(data)
            input_win.move(cursory, cursorx)
            input_win.cursyncup()
            input_win.noutrefresh()
            output_win.noutrefresh()
            screen_needs_update = True

def chatThread(sock, smp_match, onion):
    global screen_needs_update, axolotl, stdscr, input_win, \
           output_win, textpad, text_color
    stdscr, input_win, output_win = windowFactory()
    y, x = output_win.getmaxyx()
    output_win.move(y-1, 0)
    if smp_match:
        text_color = curses.color_pair(2) # green
    else:
        text_color = curses.color_pair(1) # red
    input_win.attron(text_color)
    input_win.addstr(0, 0, NICK + ':> ')
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True
    t = threading.Thread(target=receiveThread,
                         args=(sock, text_color, onion))
    t.daemon = True
    t.start()
    try:
        while True:
            with winlock:
                data = textpad.edit(validator)
                if len(data) != 0 and chr(127) not in data:
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
                        with cryptlock:
                            sock.send(axolotl.encrypt(data) + 'EOP')
                    except socket.error:
                        input_win.addstr('Disconnected')
                        input_win.refresh()
                        closeWindows(stdscr)
                        sys.exit()
                    if NICK+':> .quit' in data:
                        closeWindows(stdscr)
                        print 'Notifying the other party that you are quitting...'
                        sys.exit()
                    elif NICK+':> .send ' in data:
                        t = threading.Thread(target=uploadThread,
                                             args=(onion,data))
                        t.start()
                else:
                    input_win.addstr(NICK+':> ')
                    input_win.move(0, len(NICK)+3)
                    input_win.cursyncup()
                    input_win.noutrefresh()
                    screen_needs_update = True
            if screen_needs_update:
                curses.doupdate()
                screen_needs_update = False
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
                  'CookieAuthentication': '1',
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
        controller.authenticate()
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
    controller.authenticate()
    try:
        hs = controller.create_ephemeral_hidden_service([PORT,
                                                        CLIENT_FILE_TX_PORT,
                                                        SERVER_FILE_TX_PORT],
                                                        basic_auth={'axotor': None},
                                                        await_publication=True)
    except Exception as e:
        print e
    return controller, hs.client_auth['axotor'], hs.service_id +'.onion'

def credentialsSend(mkey, cookie, ratchet_key, onion):
    w = WHMgr(unicode(mkey),
              cookie+'___'+ratchet_key+'___'+onion,
              u'tcp:127.0.0.1:'+unicode(TOR_SERVER_CONTROL_PORT))
    w.send()
    w.run()
    return w.confirmed

def credentialsReceive(mkey):
    w = WHMgr(unicode(mkey), None, u'tcp:127.0.0.1:'+unicode(TOR_CLIENT_CONTROL_PORT))
    w.receive()
    w.run()
    return w.data

def smptest(secret, sock, is_server):
    global axolotl
    # Create an SMP object with the calculated secret
    smp = SMP(secret)

    if is_server:
        # Do the SMP protocol
        buffer = sock.recv(2439, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = axolotl.decrypt(buffer[:-padlength])
        buffer = smp.step2(buffer)
        buffer = axolotl.encrypt(buffer)
        padlength = 4539-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(3469, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = axolotl.decrypt(buffer[:-padlength])
        buffer = smp.step4(buffer)
        buffer = axolotl.encrypt(buffer)
        padlength = 1369-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

    else:
        # Do the SMP protocol
        buffer = smp.step1()
        buffer = axolotl.encrypt(buffer)
        padlength = 2439-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(4539, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = axolotl.decrypt(buffer[:-padlength])
        buffer = smp.step3(buffer)
        buffer = axolotl.encrypt(buffer)
        padlength = 3469-len(buffer)
        buffer = buffer+padlength*chr(padlength) # pad to fixed length
        sock.send(buffer)

        buffer = sock.recv(1369, socket.MSG_WAITALL)
        padlength = ord(buffer[-1:])
        buffer = axolotl.decrypt(buffer[:-padlength])
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
    global axolotl
    ans = raw_input('Run SMP authentication step? (y/N)? ')
    if not ans == 'y': ans = 'N'
    sock.send(axolotl.encrypt(ans))
    data = sock.recv(125, socket.MSG_WAITALL)
    data = axolotl.decrypt(data)
    if ans == 'N' and data == 'y':
        print 'Other party requested SMP authentication'
    if ans == 'y' or data == 'y':
        print 'Performing per-session SMP authentication...'
        ans = getpass('Enter SMP secret: ')
        print 'Running SMP protocol...'
        secret = ans + axolotl.state['CONVid']
        smp_match = smptest(secret, sock, is_server)
        if not smp_match:
            ans = raw_input('Continue? (y/N) ')
            if ans != 'y':
                print 'Exiting...'
                sys.exit()
    else:
        print 'OK - skipping SMP step and assuming ' + \
              'the other party is already authenticated...'
        smp_match = True
        sleep(2)
    return smp_match

if __name__ == '__main__':
    global axolotl
    try:
        mode = sys.argv[1]
    except:
        usage()

    NICK = raw_input('Enter your nick: ')
    OTHER_NICK = 'x'
    winlock = threading.Lock()
    transferlock = threading.Lock()
    cryptlock = threading.Lock()
    screen_needs_update = False
    HOST = '127.0.0.1'
    PORT=50000
    mkey = getpass('What is the masterkey (format: NNN-xxxx)? ')

    if mode == '-s':
        axolotl = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        axolotl.createState(other_name=OTHER_NICK,
                           mkey=hash_(mkey),
                           mode=False)
        tor_process = tor(TOR_SERVER_PORT,
                          TOR_SERVER_CONTROL_PORT,
                          '/tmp/tor.server',
                          '')
        hs, cookie, onion = ephemeralHiddenService()
        print 'Exchanging credentials via tor...'
        if credentialsSend(mkey,
                           cookie,
                           b2a(axolotl.state['DHRs']).strip(),
                           onion):
            pass
        else:
            sys.exit(1)
        print 'Credentials sent, waiting for the other party to connect...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            print 'Connected...'
            smp_match = doSMP(conn, True)
            chatThread(conn, smp_match, None)

    elif mode == '-c':
        axolotl = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        tor_process = tor(TOR_CLIENT_PORT,
                          TOR_CLIENT_CONTROL_PORT,
                          '/tmp/tor.client',
                          '')
        print 'Exchanging credentials via tor...'
        creds = credentialsReceive(mkey)
        if not creds:
            print 'Master Key Mismatch!'
            print 'Exiting...'
            sys.exit()
        cookie, rkey, onion = creds.split('___')
        controller = clientController(cookie, onion)
        axolotl.createState(other_name=OTHER_NICK,
                      mkey=hash_(mkey),
                      mode=True,
                      other_ratchetKey=a2b(rkey))

        print 'Credentials received, connecting to the other party...'
        with torcontext() as s:
            s.connect((onion, PORT))
            print 'Connected...'
            smp_match = doSMP(s, False)
            chatThread(s, smp_match, onion)

    else:
        usage()
