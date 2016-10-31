import errno
import os


DEFAULT_DB = './axolotl.db'

PLAINTEXT = 'message {}'

EXCHANGE_IDS = list()
EXCHANGES = list()


def remove_db(file_path=DEFAULT_DB):
    try:
        os.remove(file_path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def encrypt(axolotl, i, pt, ct):
    ct.append(axolotl.encrypt(pt[i]))


def decrypt(axolotl, i, pt, ct):
    assert axolotl.decrypt(ct[i]) == pt[i]


def exchange_0(a, b):
    pt = [PLAINTEXT.format(i) for i in range(14)]
    ct = list()

    encrypt(a, 0, pt, ct)
    encrypt(a, 1, pt, ct)
    encrypt(b, 2, pt, ct)
    decrypt(b, 0, pt, ct)
    decrypt(b, 1, pt, ct)
    decrypt(a, 2, pt, ct)
    encrypt(a, 3, pt, ct)
    encrypt(a, 4, pt, ct)
    encrypt(b, 5, pt, ct)
    encrypt(a, 6, pt, ct)
    encrypt(b, 7, pt, ct)
    encrypt(a, 8, pt, ct)
    encrypt(a, 9, pt, ct)
    encrypt(a, 10, pt, ct)
    encrypt(a, 11, pt, ct)
    decrypt(b, 11, pt, ct)
    decrypt(b, 3, pt, ct)
    decrypt(b, 9, pt, ct)
    decrypt(a, 5, pt, ct)
    decrypt(a, 7, pt, ct)
    decrypt(b, 4, pt, ct)
    encrypt(b, 12, pt, ct)
    decrypt(a, 12, pt, ct)
    encrypt(a, 13, pt, ct)
    decrypt(b, 13, pt, ct)
    decrypt(b, 6, pt, ct)


def exchange_1(a, b):
    n = 3
    pt = list()
    ct = list()

    for i in range(n):
        pt.append(PLAINTEXT.format(i))
        encrypt(a, i, pt, ct)

    for i in range(n):
        decrypt(b, i, pt, ct)

    for i in range(n, n*2):
        pt.append(PLAINTEXT.format(i))
        encrypt(b, i, pt, ct)

    for i in range(n, n*2):
        decrypt(a, i, pt, ct)


def exchange_2(a, b):
    n = 3
    pt = list()
    ct = list()

    for i in range(n):
        pt.append(PLAINTEXT.format(i))
        encrypt(a, i, pt, ct)

    for i in reversed(range(n)):
        decrypt(b, i, pt, ct)

    for i in range(n, n*2):
        pt.append(PLAINTEXT.format(i))
        encrypt(b, i, pt, ct)

    for i in reversed(range(n, n*2)):
        decrypt(a, i, pt, ct)


def exchange_3(a, b):
    pt = [PLAINTEXT.format(i) for i in range(6)]
    ct = list()

    encrypt(a, 0, pt, ct)
    decrypt(b, 0, pt, ct)
    encrypt(b, 1, pt, ct)
    decrypt(a, 1, pt, ct)
    encrypt(a, 2, pt, ct)
    encrypt(a, 3, pt, ct)
    decrypt(b, 2, pt, ct)
    encrypt(b, 4, pt, ct)
    decrypt(a, 4, pt, ct)
    encrypt(a, 5, pt, ct)
    decrypt(b, 5, pt, ct)
    decrypt(b, 3, pt, ct)


for i in range(4):
    id_ = 'exchange_{}'.format(i)
    EXCHANGE_IDS.append(id_)
    EXCHANGES.append(globals()[id_])
