#!/usr/bin/env python2
from twisted.internet import reactor
from wormhole.cli.public_relay import RENDEZVOUS_RELAY
from wormhole.wormhole import wormhole
from wormhole.tor_manager import TorManager
import hashlib as h

def send(code, data, tor_port):
    """I prompt for a wormhole code, send data through the wormhole,
    and return True/False depending on whether or not the hash matched
    at the receive side.
    """

    global confirmed

    def _confirm(input_message):
        global confirmed
        if input_message == "Confirmed!":
            confirmed = True
        else:
            confirmed = False

    tor = TorManager(reactor, tor_socks_port=tor_port)
    tor.start()
    w1 = wormhole(u"axotor", RENDEZVOUS_RELAY, reactor, tor_manager=tor)
    w1.set_code(code)
    w1.send(data+h.sha256(data).hexdigest())
    d = w1.get()
    d.addCallback(_confirm)
    d.addCallback(lambda _: w1.close())
    d.addCallback(lambda _: reactor.stop())
    reactor.run()
    return confirmed


def receive(code, tor_port):
    """I prompt for a wormhole code, receive data+hash, check
    for a match, confirm or not confirm to the sender, and return
    the data payload
    """

    global data

    def _receive(inbound_message):
        global data
        data = inbound_message[:-64]
        hash = inbound_message[-64:]
        if h.sha256(data).hexdigest() == hash:
            w1.send("Confirmed!")
        else:
            w1.send("Not Confirmed!")

    tor = TorManager(reactor, tor_socks_port=tor_port)
    tor.start()
    w1 = wormhole(u"axotor", RENDEZVOUS_RELAY, reactor, tor_manager=tor)
    w1.set_code(code)
    d = w1.get()
    d.addCallback(_receive)
    d.addCallback(w1.close)
    d.addCallback(lambda _: reactor.stop())
    reactor.run()
    return data
