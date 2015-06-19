Python implementation of the Axolotl ratchet protocol.
======================================================

Overview
--------
The Axolotl ratchet is a protocol (similar to OTR) that
provides for perfect forward secrecy in (a)synchronous
communications. It uses triple Diffie-Hellman for
authentication and ECDHE for perfect forward secrecy.
The protocol is lighter and more robust than the OTR
protocol - providing better forward and future secrecy,
as well as deniability.

The protocol was developed by Trevor Perrin and Moxie
Marlinspike. Its chief use currently is in the Whisper Systems
TextSecure SMS package.

A nice writeup of the protocol is on the `Whisper Systems Blog`_.
You can find the most recent specification of the protocol
`here <https://github.com/trevp/axolotl/wiki/newversion>`_.

Installation instructions
-------------------------
If you use `pip`_, install pyaxo with::

    sudo pip install pyaxo


**pyaxo will be ready for use!**

If you do not use *pip*, first make sure that you have the
following::

    sudo apt-get install python-dev

pyaxo also uses `python-gnupg`_, `curve25519-donna`_, and `passlib`_,
and if you have *setuptools* installed, these packages will be
downloaded and installed automatically. You may need some additional
python modules as well. Check the imports list.

Finally, from pyaxo's source folder, install with::

    sudo python setup.py install

Usage
-----
There are several examples showing usage. There are also
``encrypt_pipe()`` and ``decrypt_pipe()`` methods for use in
certain applications. I haven't put together an example using
them yet, but it should be straightforward.

Protocol Update
---------------
pyaxo 0.4 was updated according to the latest (Oct 1, 2014) version
of the protocol, which changed the order of the ratcheting. For that
reason, old conversations (created with pyaxo < 0.4) might not work
properly after the update. We suggest that users update pyaxo and
restart their conversations.

Bugs, etc. should be reported to the *pyaxo* github `issues page`_.

.. _`curve25519-donna`: https://pypi.python.org/pypi/curve25519-donna
.. _`issues page`: https://github.com/rxcomm/pyaxo/issues
.. _`passlib`: https://pypi.python.org/pypi/passlib
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`python-gnupg`: https://pypi.python.org/pypi/python-gnupg/
.. _`Whisper Systems Blog`: https://whispersystems.org/blog/advanced-ratcheting/
