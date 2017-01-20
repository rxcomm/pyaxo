#!/usr/bin/env python2
import os
import hashlib as h
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from wormhole.cli.public_relay import RENDEZVOUS_RELAY
from wormhole.wormhole import wormhole
from wormhole.tor_manager import TorManager
from wormhole.timing import DebugTiming

class WHMgr(object):
    def __init__(self, code, data, tor_port):
        self._code = code
        self._tor_port = tor_port
        self._reactor = reactor
        self._timing = DebugTiming()
        self.confirmed = False
        self.data = data
        self._tmgr = TorManager(self._reactor,
                                False,
                                self._tor_port,
                                timing=self._timing)

    @inlineCallbacks
    def send(self):
        """I send data through a wormhole and return True/False
        depending on whether or not the hash matched at the receive
        side.
        """
        def _confirm(input_message):
            if input_message == 'Confirmed!':
                self.confirmed = True

        if not self._tmgr.tor_available():
            print 'tor not available'
            os._exit(1)
        yield self._tmgr.start()
        self._w = wormhole(u'axotor', RENDEZVOUS_RELAY, self._reactor,
                           self._tmgr, timing=self._timing)
        self._w.set_code(self._code)
        self._w.send(self.data+h.sha256(self.data).hexdigest())
        self._d = self._w.get()
        self._d.addCallback(_confirm)
        self._d.addCallback(lambda _: self._w.close())
        self._d.addCallback(lambda _: self._reactor.stop())
        yield self._d
        return

    @inlineCallbacks
    def receive(self):
        """I receive data+hash, check for a match, confirm or not
        confirm to the sender, and return the data payload.
        """
        def _receive(inbound_message):
            self.data = inbound_message[:-64]
            _hash = inbound_message[-64:]
            if h.sha256(self.data).hexdigest() == _hash:
                self._w.send('Confirmed!')
            else:
                self._w.send('Not Confirmed!')

        if not self._tmgr.tor_available():
            print 'tor not available'
            os._exit(1)
        yield self._tmgr.start()
        self._w = wormhole(u"axotor", RENDEZVOUS_RELAY, self._reactor,
                           self._tmgr, timing=self._timing)
        self._w.set_code(self._code)
        self._d = self._w.get()
        self._d.addCallback(_receive)
        self._d.addCallback(lambda _: self._w.close())
        self._d.addCallback(lambda _: self._reactor.stop())
        yield self._d
        return

    def run(self):
        self._reactor.run()
