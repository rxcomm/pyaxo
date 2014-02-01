Here is a toy example that you can run to see how the Axolotl ratchet works.

First, create the database by running

     ./create_states.py

This will set up the
database to include both name1 and name2 identities.

(In most cases, the two identities will be different people, and so the logistics
of doing this will be simpler).

Then create several text files to encrypt.  Encrypt a file from name1 -> name2
using the following command:

     ./name1.py -e <filename>

You can then decrypt the file using the command:

     ./name2.py -d <filename>.asc

Try encrypting multiple files in both directions. Decrypt them out of order, and try
to cause other mayhem. pyaxo should sort it all out for you.

One thing you may notice is that you can only decrypt a file once - after that,
because of the perfect forward secrecy provided by Axolotl, the key is __gone__!
