### Python implementation of the Axolotl ratchet protocol.

Install with ```sudo python setup.py install```

If you have setuptools installed, the required python-gnupg
package will be downloaded and installed automatically.

pyaxo also requires the [curve25519-donna][1] package
for doing the ECDHE calculations.  This package _won't_
be installed automatically. It can be installed by:

     git clone [https://github.com/agl/curve25519-donna][1]
     cd curve25519-donna
     sudo python setup.py install

There are several examples showing usage. There are also
```encrypt_pipe()``` and ```decrypt_pipe() methods for use in
certain applications. I haven't put together an example using
them yet, but it should be straightforward.

Bugs, etc. should be reported to the pyaxo github issues page.

   [1]: https://github.com/agl/curve25519-donna
