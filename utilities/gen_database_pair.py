#!/usr/bin/env python

"""
This script will generate a pair of databases named after two conversants.
The databases can then be securely distributed to initialize axolotl.

You will need to provide your name and the other party's name. Conversations
are identified by your name and the other person's name. The conversation
should have a unique other person's name.

If you decide not to complete the initialization process, just answer no to the
question about creating a new conversation. Nothing will be saved.

If you want to reinitialize a conversation, just run the script again.
The old conversation key data will be overwritten in the databases.
"""

import sys
import binascii
from pyaxo import Axolotl

your_name = raw_input('Your name for this conversation? ').strip()
other_name = raw_input('What is the name of the other party? ').strip()
a = Axolotl(your_name,dbname=your_name+'.db')
b = Axolotl(other_name,dbname=other_name+'.db')
a.initState(other_name, b.state['DHIs'], b.handshakePKey, b.state['DHRs'], verify=False)
b.initState(your_name, a.state['DHIs'], a.handshakePKey, a.state['DHRs'], verify=False)

a.saveState()
b.saveState()
print 'The conversation ' + your_name + ' -> ' + other_name + ' has been saved in: ' + your_name + '.db'
print 'The conversation ' + other_name + ' -> ' + your_name + ' has been saved in: ' + other_name + '.db'
