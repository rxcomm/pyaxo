"""
Code is based on:
https://github.com/shanet/Cryptully/blob/master/src/crypto/smp.py
originally written by Shane Tully and released under the LGPL.
"""
import hashlib
import os
import random
import struct

class SMP(object):
    def __init__(self, secret=None):
        # 4096-bit safe prime (RFC 3526)
        self.mod = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
        self.modOrder = (self.mod-1) / 2
        self.gen = 2
        self.match = False

        self.secret = sha256(secret)

    def step1(self):
        self.x2 = createRandomExponent()
        self.x3 = createRandomExponent()

        self.g2 = pow(self.gen, self.x2, self.mod)
        self.g3 = pow(self.gen, self.x3, self.mod)

        (c1, d1) = self.createLogProof('1', self.x2)
        (c2, d2) = self.createLogProof('2', self.x3)

        # Send g2a, g3a, c1, d1, c2, d2
        return packList(self.g2, self.g3, c1, d1, c2, d2)

    def step2(self, buff):
        (g2a, g3a, c1, d1, c2, d2) = unpackList(buff)

        if not self.isValidArgument(g2a) or not self.isValidArgument(g3a):
            raise ValueError("Invalid g2a/g3a values")

        if not self.checkLogProof('1', g2a, c1, d1):
            raise ValueError("Proof 1 check failed")

        if not self.checkLogProof('2', g3a, c2, d2):
            raise ValueError("Proof 2 check failed")

        self.g2a = g2a
        self.g3a = g3a

        self.x2 = createRandomExponent()
        self.x3 = createRandomExponent()

        r = createRandomExponent()

        self.g2 = pow(self.gen, self.x2, self.mod)
        self.g3 = pow(self.gen, self.x3, self.mod)

        (c3, d3) = self.createLogProof('3', self.x2)
        (c4, d4) = self.createLogProof('4', self.x3)

        self.gb2 = pow(self.g2a, self.x2, self.mod)
        self.gb3 = pow(self.g3a, self.x3, self.mod)

        self.pb = pow(self.gb3, r, self.mod)
        self.qb = mulm(pow(self.gen, r, self.mod), pow(self.gb2, self.secret, self.mod), self.mod)

        (c5, d5, d6) = self.createCoordsProof('5', self.gb2, self.gb3, r)

        # Sends g2b, g3b, pb, qb, all the c's and d's
        return packList(self.g2, self.g3, self.pb, self.qb, c3, d3, c4, d4, c5, d5, d6)

    def step3(self, buff):
        (g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6) = unpackList(buff)

        if not self.isValidArgument(g2b) or not self.isValidArgument(g3b) or \
           not self.isValidArgument(pb) or not self.isValidArgument(qb):
            raise ValueError("Invalid g2b/g3b/pb/qb values")

        if not self.checkLogProof('3', g2b, c3, d3):
            raise ValueError("Proof 3 check failed")

        if not self.checkLogProof('4', g3b, c4, d4):
            raise ValueError("Proof 4 check failed")

        self.g2b = g2b
        self.g3b = g3b

        self.ga2 = pow(self.g2b, self.x2, self.mod)
        self.ga3 = pow(self.g3b, self.x3, self.mod)

        if not self.checkCoordsProof('5', c5, d5, d6, self.ga2, self.ga3, pb, qb):
            raise ValueError("Proof 5 check failed")

        s = createRandomExponent()

        self.qb = qb
        self.pb = pb
        self.pa = pow(self.ga3, s, self.mod)
        self.qa = mulm(pow(self.gen, s, self.mod), pow(self.ga2, self.secret, self.mod), self.mod)

        (c6, d7, d8) = self.createCoordsProof('6', self.ga2, self.ga3, s)

        inv = self.invm(qb)
        self.ra = pow(mulm(self.qa, inv, self.mod), self.x3, self.mod)

        (c7, d9) = self.createEqualLogsProof('7', self.qa, inv, self.x3)

        # Sends pa, qa, ra, c6, d7, d8, c7, d9
        return packList(self.pa, self.qa, self.ra, c6, d7, d8, c7, d9)

    def step4(self, buff):
        (pa, qa, ra, c6, d7, d8, c7, d9) = unpackList(buff)

        if not self.isValidArgument(pa) or not self.isValidArgument(qa) or not self.isValidArgument(ra):
            raise ValueError("Invalid pa/qa/ra values")

        if not self.checkCoordsProof('6', c6, d7, d8, self.gb2, self.gb3, pa, qa):
            raise ValueError("Proof 6 check failed")

        if not self.checkEqualLogs('7', c7, d9, self.g3a, mulm(qa, self.invm(self.qb), self.mod), ra):
            raise ValueError("Proof 7 check failed")

        inv = self.invm(self.qb)
        rb = pow(mulm(qa, inv, self.mod), self.x3, self.mod)

        (c8, d10) = self.createEqualLogsProof('8', qa, inv, self.x3)

        rab = pow(ra, self.x3, self.mod)

        inv = self.invm(self.pb)
        if rab == mulm(pa, inv, self.mod):
            self.match = True

        # Send rb, c8, d10
        return packList(rb, c8, d10)

    def step5(self, buff):
        (rb, c8, d10) = unpackList(buff)

        if not self.isValidArgument(rb):
            raise ValueError("Invalid rb values")

        if not self.checkEqualLogs('8', c8, d10, self.g3b, mulm(self.qa, self.invm(self.qb), self.mod), rb):
            raise ValueError("Proof 8 check failed")

        rab = pow(rb, self.x3, self.mod)

        inv = self.invm(self.pb)
        if rab == mulm(self.pa, inv, self.mod):
            self.match = True

    def createLogProof(self, version, x):
        randExponent = createRandomExponent()
        c = sha256(version + str(pow(self.gen, randExponent, self.mod)))
        d = (randExponent - mulm(x, c, self.modOrder)) % self.modOrder
        return (c, d)

    def checkLogProof(self, version, g, c, d):
        gd = pow(self.gen, d, self.mod)
        gc = pow(g, c, self.mod)
        gdgc = gd * gc % self.mod
        return (sha256(version + str(gdgc)) == c)

    def createCoordsProof(self, version, g2, g3, r):
        r1 = createRandomExponent()
        r2 = createRandomExponent()

        tmp1 = pow(g3, r1, self.mod)
        tmp2 = mulm(pow(self.gen, r1, self.mod), pow(g2, r2, self.mod), self.mod)

        c = sha256(version + str(tmp1) + str(tmp2))

        # TODO: make a subm function
        d1 = (r1 - mulm(r, c, self.modOrder)) % self.modOrder
        d2 = (r2 - mulm(self.secret, c, self.modOrder)) % self.modOrder

        return (c, d1, d2)

    def checkCoordsProof(self, version, c, d1, d2, g2, g3, p, q):
        tmp1 = mulm(pow(g3, d1, self.mod), pow(p, c, self.mod), self.mod)

        tmp2 = mulm(mulm(pow(self.gen, d1, self.mod), pow(g2, d2, self.mod), self.mod), pow(q, c, self.mod), self.mod)

        cprime = sha256(version + str(tmp1) + str(tmp2))

        return (c == cprime)

    def createEqualLogsProof(self, version, qa, qb, x):
        r = createRandomExponent()
        tmp1 = pow(self.gen, r, self.mod)
        qab = mulm(qa, qb, self.mod)
        tmp2 = pow(qab, r, self.mod)

        c = sha256(version + str(tmp1) + str(tmp2))
        tmp1 = mulm(x, c, self.modOrder)
        d = (r - tmp1) % self.modOrder

        return (c, d)

    def checkEqualLogs(self, version, c, d, g3, qab, r):
        tmp1 = mulm(pow(self.gen, d, self.mod), pow(g3, c, self.mod), self.mod)

        tmp2 = mulm(pow(qab, d, self.mod), pow(r, c, self.mod), self.mod)

        cprime = sha256(version + str(tmp1) + str(tmp2))
        return (c == cprime)

    def invm(self, x):
        return pow(x, self.mod-2, self.mod)

    def isValidArgument(self, val):
        return (val >= 2 and val <= self.mod-2)

def packList(*items):
    buff = ''

    # For each item in the list, convert it to a byte string and add its length as a prefix
    for item in items:
        bytes = longToBytes(item)
        buff += struct.pack('!I', len(bytes)) + bytes

    return buff

def unpackList(buff):
    items = []

    index = 0
    while index < len(buff):
        # Get the length of the long (4 byte int before the actual long)
        length = struct.unpack('!I', buff[index:index+4])[0]
        index += 4

        # Convert the data back to a long and add it to the list
        item = bytesToLong(buff[index:index+length])
        items.append(item)
        index += length

    return items

def bytesToLong(bytes):
    length = len(bytes)
    string = 0
    for i in range(length):
        string += byteToLong(bytes[i:i+1]) << 8*(length-i-1)
    return string

def longToBytes(long):
    bytes = ''
    while long != 0:
        bytes = longToByte(long & 0xff) + bytes
        long >>= 8
    return bytes

def byteToLong(byte):
    return struct.unpack('B', byte)[0]

def longToByte(long):
    return struct.pack('B', long)

def mulm(x, y, mod):
    return x * y % mod

def createRandomExponent():
    return random.getrandbits(512*8)

def sha256(message):
    return long(hashlib.sha256(str(message)).hexdigest(), 16)
