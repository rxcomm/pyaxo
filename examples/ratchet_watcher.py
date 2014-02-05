#!/usr/bin/env python

import copy
import os
from pyaxo import Axolotl

name1 = 'Angie'
name2 = 'Barb'

a = Axolotl(name1, dbname='name1.db', dbpassphrase=None)
b = Axolotl(name2, dbname='name2.db', dbpassphrase=None)

a.loadState(name1, name2)
b.loadState(name2, name1)

topic = ['   My Name',
          'Other Name',
          '        RK',
          '       HKs',
          '       HKr',
          '      NHKs',
          '      NHKr',
          '       CKs',
          '       CKr',
          ' DHIs_priv',
          '      DHIs',
          '      DHIr',
          ' DHRs_priv',
          '      DHRs',
          '      DHRr',
          '    CONVid',
          '        Ns',
          '        Nr',
          '       PNs',
          '   bobs_fm',
          '      mode']

def hilite(text, c=False):
    attr = []
    if c:
        attr.append('41')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), text)

data_old = False
os.system('clear')
while True:
    print '\x1b[;32m     Name: 1 2\x1b[0m'
    print '--------------'
    a.loadState(name1, name2)
    b.loadState(name2, name1)
    databases = (a.db, b.db)
    data = []
    a_chg = False
    b_chg = False
    for number, database in enumerate(databases):
        cur = database.cursor()
        cur.execute('SELECT * from conversations')
        data += [cur.fetchall()]
    if not data_old:
        data_old = data
    for i in range(len(data[0][0])):
        if data[0][0][i] != data_old[0][0][i]: a_chg=True
        if data[1][0][i] != data_old[1][0][i]: b_chg=True
        if topic[i] == '      mode':
            if data[0][0][i] == 1:
                var = 'A'
                var2 = 'B'
            else:
                var = 'B'
                var2 = 'A'
        elif topic[i]=='        Ns' or topic[i]=='        Nr' or topic[i]=='       PNs':
            var = data[0][0][i]
            var2 = data[1][0][i]
        elif topic[i] == '   bobs_fm':
            var = 'F'
            var2 = 'F'
            if data[0][0][i] == 1:
                var = 'T'
            elif data[1][0][i] == 1:
                var2 = 'T'
        else:
            var = '*'
            var2 = '*'
        print topic[i], hilite(var, a_chg), hilite(var2, b_chg)
        a_chg = False
        b_chg = False
    print '--------------'
    ans = raw_input('Load new state? ')
    if ans=='q' or ans=='n': exit()
    os.system('clear')
    data_old = data
