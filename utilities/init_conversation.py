#!/usr/bin/env python

"""
This script will add a new conversation between two parties to the
axolotl database.

You will need to provide the other party's name, identity key, handshake key,
and ratchet key. Conversations are identified by your name and the other person's
name. Each conversation should have a unique other person's name. Your name can be
the same for each conversation or different for each one or any combination.

If you decide not to complete the initialization process, just answer no to the
question about creating a new conversation. Nothing will be saved.

If you want to reinitialize a conversation, just run the script again.
The old conversation key data will be overwritten in the database.
"""

import sys
import binascii
from pyaxo import Axolotl

your_name = raw_input('Your name for this conversation? ').strip()
a = Axolotl(your_name)
a.printKeys()

ans = raw_input('Do you want to create a new conversation? y/N ').strip()
if ans == 'y':
    other_name = raw_input('What is the name of the other party? ').strip()
    identity = raw_input('What is the identity key for the other party? ').strip()
    handshake = raw_input('What is the handshake key for the other party? ').strip()
    ratchet = raw_input('What is the ratchet key for the other party? ').strip()
    a.initState(other_name, binascii.a2b_base64(identity), binascii.a2b_base64(handshake),
                binascii.a2b_base64(ratchet))
    a.saveState()
    print 'The conversation ' + your_name + ' -> ' + other_name + ' has been saved.'
else:
    print 'OK, nothing has been saved...'

