#!/usr/bin/env python2
import os
import hashlib as h
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from wormhole.cli.public_relay import RENDEZVOUS_RELAY
import wormhole
from wormhole.tor_manager import get_tor
from wormhole.timing import DebugTiming

class WHMgr(object):
    def __init__(self, code, data, tor_port):
        self._code = code
        self._tor_port = tor_port
        self._reactor = reactor
        self._timing = DebugTiming()
        self.confirmed = False
        self.data = data

    @inlineCallbacks
    def start_tor(self):
        self._tor = yield get_tor(self._reactor,
                                  launch_tor=False,
                                  tor_control_port=self._tor_port,
                                  timing=self._timing)
        return

    @inlineCallbacks
    def send(self):
        """I send data through a wormhole and return True/False
        depending on whether or not the hash matched at the receive
        side.
        """
        def _confirm(input_message):
            if input_message == 'Confirmed!':
                self.confirmed = True

        yield self.start_tor()
        self._w = wormhole.create(u'axotor', RENDEZVOUS_RELAY, self._reactor,
                                  tor=self._tor, timing=self._timing)
        self._w.set_code(self._code)
        self._w.send_message(self.data+h.sha256(self.data).hexdigest())
        yield self._w.get_message().addCallback(_confirm)
        yield self._w.close()
        self._reactor.stop()
        return

    @inlineCallbacks
    def receive(self):
        """I receive data+hash, check for a match, confirm or not
        confirm to the sender, and return the data payload.
        """
        def _receive(input_message):
            self.data = input_message[:-64]
            _hash = input_message[-64:]
            if h.sha256(self.data).hexdigest() == _hash:
                self._w.send_message('Confirmed!')
            else:
                self._w.send_message('Not Confirmed!')

        yield self.start_tor()
        self._w = wormhole.create(u'axotor', RENDEZVOUS_RELAY, self._reactor,
                                  tor=self._tor, timing=self._timing)
        self._w.set_code(self._code)
        yield self._w.get_message().addCallback(_receive)
        yield self._w.close()
        self._reactor.stop()
        return

    def run(self):
        self._reactor.run()
