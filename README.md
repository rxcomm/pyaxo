### Python implementation of the Axolotl ratchet protocol.

#### Overview

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

A nice writeup of the protocol is [on the Whisper Systems Blog][2].
You can find the most recent specification of the protocol [here][3].

#### Installation instructions

Install with ```sudo python setup.py install```

If you have setuptools installed, the required python-gnupg
package will be downloaded and installed automatically.

pyaxo also requires the [curve25519-donna][1] package
for doing the ECDHE calculations.  This package _won't_
be installed automatically. It can be installed by:

     git clone https://github.com/agl/curve25519-donna
     cd curve25519-donna
     sudo python setup.py install

You may need some additional python modules as well. Check
the imports list.

There are several examples showing usage. There are also
```encrypt_pipe()``` and ```decrypt_pipe()``` methods for use in
certain applications. I haven't put together an example using
them yet, but it should be straightforward.

Bugs, etc. should be reported to the pyaxo github issues page.

   [1]: https://github.com/agl/curve25519-donna
   [2]: https://whispersystems.org/blog/advanced-ratcheting/
   [3]: https://github.com/trevp/axolotl/wiki/newversion
