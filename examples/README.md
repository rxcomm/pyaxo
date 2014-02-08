Here is a toy example that you can run to see how the Axolotl ratchet works.

First, create the database by running

     ./create_states.py

This will set up two databases - one for each of the name1 and name2 identities.
The databases will be unencrypted. You can set a passphrase with the
dbpassphrase kwarg, or leave it out to have the system prompt for a passphrase.

Then create several text files to encrypt.  Encrypt a file from name1 -> name2
using the following command:

     ./name1.py -e <filename>

You can then decrypt the file using the command:

     ./name2.py -d <filename>.asc

Try encrypting multiple files in both directions. Decrypt them out of order, and try
to cause other mayhem. pyaxo should sort it all out for you.

I've also added ```ratchet_viewer.py```, a utility that you can use to view
the ratchet state as it changes. After you've initialized the name1/name2 
databases, run ```ratchet_viewer.py``` in another window in the same directory.
Load the new state as you encrypt/decrypt files and it will show you the changes.

One thing you may notice is that you can only decrypt a file once - after that,
because of the perfect forward secrecy provided by Axolotl, the key is __gone__!

Finally, there is a file transfer example ```transfer.py```, and a standalone chat
program ```axochat.py```. These illustrate the use of a context manager with Axolotl.
