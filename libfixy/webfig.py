import hashlib
import struct
import codecs
import urllib.parse
import asyncio
import io
import logging
import curve25519
from passlib.utils import des
from passlib.hash import nthash

MASK_FTYPE = 0xf8000000
# FT_BOOL = (0 << 27)
# FT_U32 = (1 << 27)
# FT_U64 = (2 << 27)
# FT_ADDR6 = (3 << 27)
# FT_STRING = (4 << 27)
# FT_MESSAGE = (5 << 27)
# FT_RAW = (6 << 27)
# FT_BOOL_ARRAY = (16 << 27)
# FT_U32_ARRAY = (17 << 27)
# FT_U64_ARRAY = (18 << 27)
# FT_ADDR6_ARRAY = (19 << 27)
# FT_STRING_ARRAY = (20 << 27)
# FT_MESSAGE_ARRAY = (21 << 27)
# FT_RAW_ARRAY = (22 << 27)
# FS_SHORT = (1 << 24)
FT_BOOL = 0x0
FT_U32 = 0x8000000
FT_U64 = 0x10000000
FT_ADDR6 = 0x18000000
FT_STRING = 0x20000000
FT_MESSAGE = 0x28000000
FT_RAW = 0x30000000
FT_BOOL_ARRAY = 0x80000000
FT_U32_ARRAY = 0x88000000
FT_U64_ARRAY = 0x90000000
FT_ADDR6_ARRAY = 0x98000000
FT_STRING_ARRAY = 0xa0000000
FT_MESSAGE_ARRAY = 0xa8000000
FT_RAW_ARRAY = 0xb0000000
FS_SHORT = 0x1000000

LOGGER = logging.getLogger(__name__)


class MsChapV2:
    """MS-CHAP-V2 challenge-response implementation."""
    # https://tools.ietf.org/html/rfc3079#section-3.4
    magic1 = b'This is the MPPE Master Key'
    magic2 = b'On the client side, this is the send key; on the server side, it is the receive key.'
    magic3 = b'On the client side, this is the receive key; on the server side, it is the send key.'
    shapad1 = b'\x00' * 40
    shapad2 = b'\xf2' * 40

    def gen_nt_response(self, server_chal, peer_chal, username, password):
        if isinstance(server_chal, str):
            server_chal = bytes(server_chal, 'utf8')
        if isinstance(peer_chal, str):
            peer_chal = bytes(peer_chal, 'utf8')

        self.server_chal = server_chal
        self.peer_chal = peer_chal
        self.username = username
        self.password = password
        challange_hash = self._gen_challenge_hash()
        nt_hash = self._gen_nt_hash()
        return self._gen_challenge_response(challange_hash, nt_hash)

    def _gen_challenge_hash(self):
        sha1 = hashlib.sha1()
        sha1.update(self.peer_chal)
        sha1.update(self.server_chal)
        if isinstance(self.username, str):
            self.username = self.username.encode('utf-8')
        sha1.update(self.username)
        return sha1.digest()[:8]

    def _gen_nt_hash(self, password=None):
        if not password:
            password = self.password
        return nthash.raw_nthash(password)

    @staticmethod
    def _gen_nt_hash_hash(nt_hash):
        md4 = hashlib.new('md4')
        md4.update(nt_hash)
        return md4.digest()

    def _gen_challenge_response(self, challenge_hash, nt_hash):
        _nt_hash = b''.join((nt_hash, b'\x00' * 5))
        challenge_response = b''
        key = des.expand_des_key(_nt_hash[:7])
        challenge_response += des.des_encrypt_block(key, challenge_hash)
        key = des.expand_des_key(_nt_hash[7:14])
        challenge_response += des.des_encrypt_block(key, challenge_hash)
        key = des.expand_des_key(_nt_hash[14:])
        challenge_response += des.des_encrypt_block(key, challenge_hash)
        return challenge_response

    def mppe_chap2_gen_keys(self, nt_response):
        nt_hash = self._gen_nt_hash()
        nt_hash_hash = self._gen_nt_hash_hash(nt_hash)
        master_key = self._mppe_gen_master_key(nt_hash_hash, nt_response)
        master_recv_key = self._get_asymetric_start_key(master_key, 16, True, True)
        master_send_key = self._get_asymetric_start_key(master_key, 16, False, True)
        self.recv_key = master_recv_key
        self.send_key = master_send_key
        return (master_recv_key, master_send_key)

    def _mppe_gen_master_key(self, password_hash_hash, nt_response):
        sha1 = hashlib.sha1()
        sha1.update(password_hash_hash)
        sha1.update(nt_response)
        sha1.update(self.magic1)
        return sha1.digest()[:16]

    def _get_asymetric_start_key(self, master_key, session_key_length, is_send, is_server):
        if is_send:
            if is_server:
                s = self.magic3
            else:
                s = self.magic2
        else:
            if is_server:
                s = self.magic2
            else:
                s = self.magic3
        sha1 = hashlib.sha1()
        sha1.update(master_key)
        sha1.update(self.shapad1)
        sha1.update(s)
        sha1.update(self.shapad2)
        return sha1.digest()[:session_key_length]


class RC4:
    """RC4 implementation for WebFig"""
    def __init__(self):
        self.S = []
        self.i = 0
        self.j = 0

    def set_key(self, key):
        j = 0
        self.S = [x for x in range(256)]
        for i in range(256):
            j = (j + key[i % len(key)] + self.S[i]) & 255
            self.S[i], self.S[j] = self.S[j], self.S[i]

        self.i = 0
        self.j = 0
        for i in range(768):
            self.gen()

    def gen(self):
        i = self.i = (self.i + 1) & 255
        j = self.j = (self.j + self.S[i]) & 255
        self.S[i], self.S[j] = self.S[j], self.S[i]
        return self.S[(self.S[i] + self.S[j]) & 255]

    def encrypt(self, data):
        data = bytes(data, 'utf8')
        o = []
        for i in data:
            c = i ^ self.gen()
            if not c:
                c = 256
            o.append(chr(c))
        o = ''.join(o)
        return bytes(o, 'utf8')

    def encrypt_retkey(self, data):
        """Returns ciphertext and the key used for encryption."""
        data = bytes(data, 'utf8')
        o = []
        k = []
        for i in data:
            _k = self.gen()
            k.append(_k)
            c = i ^ _k
            if not c:
                c = 256
            o.append(chr(c))
        o = ''.join(o)
        k = ''.join(k)
        return bytes(o, 'utf8'), bytes(k, 'utf8')

    def decrypt(self, data):
        _data = codecs.decode(data)[8:]
        data = b''
        for i in _data:
            data += struct.pack('B', ord(i) & 0xff)
        o = []
        for i in data:
            o.append(chr((i & 0xff) ^ self.gen()))
        return ''.join(o)

    def decrypt_retkey(self, _data):
        """Returns plaintext and the key used for decryption."""
        if isinstance(_data, bytes):
           _data = codecs.decode(_data)
        data = b''
        for i in _data:
            data += struct.pack('B', ord(i) & 0xff)
        o = []
        k = []
        for i in data:
            _k = self.gen()
            k.append(_k)
            o.append(chr((i & 0xff) ^ _k))
        return ''.join(o), k

    def crypt_msg_retkey(self, data):
        o = []
        k = []
        for v in data:
            _k = self.gen()
            k.append(_k)
            o.append(chr(v ^ _k))
        return ''.join(o), k


class Session:
    """WebFig session implementation"""
    # The hardcoded peer challenge from the original code (!@#$%^&*()_+:3|~)
    peerchal = b'\x21\x40\x23\x24\x25\x5e\x26\x2a\x28\x29\x5f\x2b\x3a\x33\x7c\x7e'
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.mschap = MsChapV2()
        self.txseq = 0
        self.txenc = RC4()
        self.txqueue = dict()
        self.rxseq = 0
        self.rxenc = RC4()
        self.rxqueue = dict()
        self.padding= '        '
        self.id = None
        self.authenticated = False
        self.response = None
        self.privkey = None

    def is_authenticated(self):
        return self.authenticated

    def set_authenticated(self):
        self.authenticated = True

    @staticmethod
    def canonicalize_bytes(s):
        """
        This function canonicalize bytes that will be sent to the server.
        The implementation mimics the original implementation in order
        to generate proper byte sequences.

        :param s: Bytes that should be encoded
        :return: Same bytes that will be generated by the original code
        """
        if isinstance(s, str):
            s = bytes(s, 'utf8')
        if isinstance(s, bytes):
            s = [i for i in s]
        elif isinstance(s, int):
            s = [s]
        else:
            return False
        _o = []
        for i in s:
            i &= 0xff
            if not i:
                i = 256
            _o.append(bytes(chr(i), 'utf8'))
        return b''.join(_o)

    @staticmethod
    def pack_bytes(s):
        """Pack bytes received from WebFig in order use them for calculations."""
        o = b''
        for i in s:
            o += struct.pack('B', ord(i) & 0xff)
        return o

    @staticmethod
    def unpack_bytes(s):
        """Unpack bytes for sending to WebFig."""
        o = b''
        for i in s:
            i = bytes(chr(i), 'utf8')
            o += struct.pack('{}s'.format(len(i)), i)
        return o

    def make_response(self, response, username=None, password=None):
        """
        Generate a MS-CHAP-V2 authentication response.

        :param response: Initial response from the server (contains server challenge)
        :param username: Username
        :param password: Password
        :return: Returns the complete message that should be sent back to the server
        """
        if username:
            self.username = username
        if password:
            self.password = password

        # Generate the MS-CHAP-V2 response for authentication
        response = self.pack_bytes(codecs.decode(response))
        self.id = struct.unpack('!I', response[:4])[0]
        self.seq = struct.unpack('!I', response[4:8])[0]
        authchal = response[8:]
        nt_response = self.mschap.gen_nt_response(authchal, self.peerchal, self.username, self.password)
        ret = self.canonicalize_bytes(struct.pack('!I', self.id))
        ret += self.canonicalize_bytes(struct.pack('!I', 0))
        ret += self.unpack_bytes(authchal)
        ret += self.canonicalize_bytes(struct.pack('!H', 0))
        ret += self.peerchal
        ret += self.canonicalize_bytes(struct.pack('!Q', 0))
        ret += self.unpack_bytes(nt_response)
        ret += bytes(self.username, 'utf8')
        # Derive encryption keys based on MS-CHAP-V2 authentication data
        recv_key, send_key = self.mschap.mppe_chap2_gen_keys(nt_response)
        self.rxenc.set_key(recv_key)
        self.txenc.set_key(send_key)
        self.txseq = 1
        self.rxseq = 1
        self.response = ret

    def make_response_curve25519(self):
        """
        Generate a MS-CHAP-V2 authentication response.

        :return: Returns the complete message that should be sent back to the server
        """

        # Generate the MS-CHAP-V2 response for authentication

        ret = self.canonicalize_bytes(struct.pack('!I', 0))
        ret += self.canonicalize_bytes(struct.pack('!I', 0))

        # TODO: implement curve25519 stuff
        #random_key = b'A' * 32
        #self.privkey = curve25519.Private(secret=random_key)
        secret = b'\x00' * 32
        self.privkey = curve25519.Private(secret=secret)
        pubkey = self.privkey.get_public()
        # TODO: go to be pubkey.public.reverse()?
        ret += pubkey.public
        self.response = ret

    @staticmethod
    def curve_a2u(data):
        r = [0 for _ in range(16)]
        for i in range(32):
            r[i >> 1] |= data[31 - i] << (i & 1) * 8
        return r

    @staticmethod
    def curve_u2a(data):
        r = bytearray(32)
        for i in range(32):
            r[31 - i] = (data[i >> 1] >> ((i & 1) * 8)) & 0xff
        return r

    @staticmethod
    def str2a(data):
        r = []
        for i in data:
            r.append(chr(i & 0xff))
        return r

    @staticmethod
    def a2str(data):
        def pack_bytes(s):
            #o = b''
            #for i in s:
            #   o += struct.pack('B', ord(i) & 0xff)
            #return o
            return struct.pack('B', s & 0xff)
        r = []
        for i in data:
            #r.append(self.pack_bytes(data[i]))
            r.append(pack_bytes(i))
        return b''.join(r)

    @staticmethod
    def rev_bytes(x):
        r = bytearray(x)
        r.reverse()
        return bytes(r)

    def decode_key_material_transit(self, data):
        # skip first 16 byes (skips 8 in javascript)
        #pubkey = ir[16:]
        c = self.str2a(data)
        x = [ord(x) for x in c]
        e = self.curve_a2u(x)
        f = [(x).to_bytes(2, byteorder='big') for x in e]
        pubkey_decoded = b''.join(f)
        return pubkey_decoded

    def encode_key_material_transit(self, data):
        key_encoded = b''
        return key_encoded

    def key_exchange_curve25519(self, response):
        response = self.pack_bytes(codecs.decode(response))
        id = struct.unpack('!I', response[:4])[0]
        rpubkey = response[8:]
        LOGGER.debug('rpubkey: ' + codecs.encode(rpubkey, 'hex').decode())

        # TODO: if the other stuff works, maybe use this wrapper?
        #shared_key = self.privkey.get_shared_key(rpubkey, hashfunc=lambda d:d)

        secret = b'\x00' * 32
        self.privkey = curve25519.Private(secret=secret)

        priv = self.privkey.private
        # TODO: is reversing really required?
        pub = self.rev_bytes(rpubkey)
        shared_key = curve25519._curve25519.make_shared(priv, pub)
        # TODO: is reversing really required?
        shared_key = self.rev_bytes(shared_key)
        LOGGER.debug('shared key: ' + codecs.encode(shared_key, 'hex').decode())

        ms = MsChapV2()
        recv_key = ms._get_asymetric_start_key(shared_key, 16, True, True)
        send_key = ms._get_asymetric_start_key(shared_key, 16, False, True)
        LOGGER.debug('recv_key: ' + codecs.encode(recv_key, 'hex').decode())
        LOGGER.debug('send_key: ' + codecs.encode(send_key, 'hex').decode())

        self.rxenc.set_key(recv_key)
        self.txenc.set_key(send_key)
        self.txseq = 1
        self.rxseq = 1

    def encrypt(self, data):
        self.txseq += len(data) + 8
        o = b''
        o += self.canonicalize_bytes(struct.pack('!I', self.id))
        o += self.canonicalize_bytes(struct.pack('!I', 1))
        o += self.txenc.encrypt(data)
        o += self.txenc.encrypt(self.padding)
        return o

    def decrypt(self, data):
        if len(data) < 8 + 8:
            return
        self.rxseq += len(data) - 8
        return self.rxenc.decrypt(data)

    @staticmethod
    def encrypt_with_key(data, key):
        """Encrypt data with a supplied key. Can be called at
        any time, will not influence the key scheduling."""
        if isinstance(data, str):
            data = bytes(data, 'utf8')
        o = []
        for i, v in enumerate(data):
            c = v ^ key[i]
            if not c:
                c = 256
            o.append(chr(c))
        o = ''.join(o)
        return bytes(o, 'utf8')

    @staticmethod
    def decrypt_with_key(data, key):
        """Decrypt data with a supplied key. Can be called at
        any time, will not influence the key scheduling."""
        _data = codecs.decode(data)[8:]
        data = b''
        for i in _data:
            data += struct.pack('B', ord(i) & 0xff)
        o = []
        for i, v in enumerate(data):
            o.append(chr((v & 0xff) ^ key[i]))
        return ''.join(o)

    def tx_encrypt_uri(self, query_string):
        """Encrypt an URI for WebFig."""
        enc = self.txenc.encrypt(query_string)
        query_string = self.unpack_bytes(enc)
        return urllib.parse.quote(query_string)

    @asyncio.coroutine
    def tx_decrypt_uri(self, query_string):
        """Decrypt an URI sent from the client to WebFig."""
        query_string = urllib.parse.unquote_to_bytes(query_string)
        p, k = yield from self.tx_decrypt(query_string)
        return p, k

    @asyncio.coroutine
    def tx_decrypt(self, data):
        """Decrypt traffic sent from the client to WebFig."""
        if isinstance(data, str):
            _data = data
        else:
            _data = codecs.decode(data)
        __data = self.pack_bytes(_data)
        if len(data) < 8 + 8:
            return
        id = struct.unpack('!I', __data[:4])[0]
        seq = struct.unpack('!I', __data[4:8])[0]
        if self.id != id:
            pass
        if self.txseq != seq:
            self.txqueue[seq] = _data
            _data = yield from self.tx_dequeue()
        _data = _data[8:]
        self.txseq += len(_data)
        p, k = self.txenc.decrypt_retkey(_data)
        return p, k

    @asyncio.coroutine
    def tx_decrypt_msg(self, data):
        if len(data) < 8 + 8:
            return None, None
        id = struct.unpack('!I', data[:4])[0]
        seq = struct.unpack('!I', data[4:8])[0]
        if self.id != id:
            pass
        if self.txseq != seq:
            self.txqueue[seq] = data
            #data = yield from self.tx_dequeue()
            return None, None
        data = data[8:]
        self.txseq += len(data)
        p, k = self.txenc.crypt_msg_retkey(data)
        return p, k

    @asyncio.coroutine
    def tx_dequeue(self, msg=False):
        # while True:
        #     data = self.txqueue.get(self.txseq)
        #     if not data:
        #         return
        #     #if not data:
        #     #    yield from asyncio.sleep(1)
        #     #    continue
        #     del self.txqueue[self.txseq]
        #     break
        data = self.txqueue.get(self.txseq)
        if data:
            del self.txqueue[self.txseq]
            if msg:
                return self.tx_decrypt_msg(data)
            else:
                return self.tx_decrypt(data)

    def rx_decrypt(self, data):
        """Decrypt traffic sent from WebFig to the client."""
        _data = codecs.decode(data)
        __data = self.pack_bytes(_data)
        if len(data) < 8 + 8:
            return
        id = struct.unpack('!I', __data[:4])[0]
        seq = struct.unpack('!I', __data[4:8])[0]
        if self.id != id:
            pass
        if self.rxseq != seq:
            self.rxqueue[seq] = data
            return None, None
        self.rxseq += len(_data) - 8
        _data = _data[8:]
        p, k = self.rxenc.decrypt_retkey(_data)
        return p, k

    @asyncio.coroutine
    def rx_decrypt_msg(self, data):
        if len(data) < 8 + 8:
            return None, None
        id = struct.unpack('!I', data[:4])[0]
        seq = struct.unpack('!I', data[4:8])[0]
        if self.id != id:
            pass
        if self.rxseq != seq:
            self.rxqueue[seq] = data
            return None, None
        self.rxseq += len(data) - 8
        data = data[8:]
        p, k = self.rxenc.crypt_msg_retkey(data)
        return p, k

    @asyncio.coroutine
    def rx_dequeue(self, msg=False):
        # while True:
        #     data = self.rxqueue.get(self.rxseq)
        #     if data:
        #         break
        #         del self.rxqueue[self.rxseq]
        data = self.rxqueue.get(self.rxseq)
        if data:
            del self.rxqueue[self.rxseq]
            if msg:
                return self.rx_decrypt_msg(data)
            else:
                return self.rx_decrypt(data)

    def msg2buffer(self, msg):
        arr = [0 for _ in range(64 * 1024)]
        pos = 0
        pos += 1
        arr[pos] = 0x4d
        pos += 1
        arr[pos] = 0x32

        def writeId(idtype, idstr, pos=pos):
            t = idstr[1:]
            if not t:
                t = '0'
            #x = int(idstr[1:], 16)
            x = int(t, 16)
            pos += 1
            arr[pos] = x
            pos += 1
            arr[pos] = x >> 8
            pos += 1
            arr[pos] = x >> 16
            pos += 1
            arr[pos] = idtype >> 24

        def write16(val, pos=pos):
            pos += 1
            arr[pos] = val & 0xff
            pos += 1
            arr[pos] = (val >> 8) & 0xff

        def write32(val, pos=pos):
            pos += 1
            arr[pos] = val & 0xff
            pos += 1
            arr[pos] = (val >> 8) & 0xff
            pos += 1
            arr[pos] = (val >> 16) & 0xff
            pos += 1
            arr[pos] = (val >> 24) & 0xff

        def write64(val, pos=pos):
            pos += 1
            arr[pos] = val & 0xff
            pos += 1
            arr[pos] = (val >> 8) & 0xff
            pos += 1
            arr[pos] = (val >> 16) & 0xff
            pos += 1
            arr[pos] = (val >> 24) & 0xff
            temp = val / 4294967296
            pos += 1
            arr[pos] = temp & 0xff
            pos += 1
            arr[pos] = (temp >> 8) & 0xff
            pos += 1
            arr[pos] = (temp >> 16) & 0xff
            pos += 1
            arr[pos] = (temp >> 24) & 0xff

        for r in msg:
            pfx = r[0]
            if pfx == '_':
                continue
            #val = msg[r]
            val = r
            if pfx == 'b':
                writeId(FT_BOOL | val if FS_SHORT else 0, r)
            elif pfx == 'u':
                if val >= 0 and val < 256:
                    writeId(FT_U32 | FS_SHORT, r)
                    pos += 1
                    arr[pos] = val
                else:
                    writeId(FT_U32, r)
                    write32(val)
            elif pfx == 'q':
                writeId(FT_U64, r)
                write64(val)
            elif pfx == 'a':
                writeId(FT_ADDR6, r)
                for i in range(16):
                    pos += 1
                    arr[pos] = val[i]
            elif pfx == 's':
                if len(val) > 256:
                    writeId(FT_STRING | FS_SHORT, r)
                    pos += 1
                    arr[pos] = len(val)
                else:
                    writeId(FT_STRING, r)
                    write16(len(val))
                for i in range(len(val)):
                    pos += 1
                    arr[pos] = val[i]
            elif pfx == 'r':
                if len(val) < 256:
                    writeId(FT_RAW | FS_SHORT, r)
                    pos += 1
                    arr[pos] = val.length
                else:
                    writeId(FT_RAW, r)
                    write16(len(val))
                for i in range(len(val)):
                    pos += 1
                    arr[pos] = val[i]
            elif pfx == 'm':
                x = self.msg2buffer(val)
                if len(x) < 256:
                    writeId(FT_MESSAGE | FS_SHORT, r)
                    pos += 1
                    arr[pos] = len(x)
                else:
                    writeId(FT_MESSAGE, r)
                    write16(len(x))
                arr[pos:pos] = x
                pos += len(x)
            elif pfx == 'B':
                writeId(FT_BOOL_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    pos += 1
                    arr[pos] = val[i]
            elif pfx == 'U':
                writeId(FT_U32_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    write32(val[i])
            elif pfx == 'Q':
                writeId(FT_U64_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    write64(val[i])
            elif pfx == 'A':
                writeId(FT_ADDR6_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    for k in range(16):
                        pos += 1
                        #arr[pos] = val[i][k]
                        arr[pos] = val[i].get(k)
            elif pfx == 'S':
                writeId(FT_STRING_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    write16(len(val[i]))
                    for k in range(len(val[i])):
                        pos += 1
                        arr[pos] = val[i][k]
            elif pfx == 'R':
                writeId(FT_RAW_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    write16(len(val[i]))
                    for k in range(len(val[i])):
                        pos += 1
                        arr[pos] = val[i][k]
            elif pfx == 'M':
                writeId(FT_MESSAGE_ARRAY, r)
                write16(len(val))
                for i in range(len(val)):
                    x = self.msg2buffer(val[i])
                    write16(len(x))
                    arr[pos:pos] = x
                    pos += len(x)
        return arr

    @staticmethod
    def int2num(v):
        return 0x100000000 if v < 0 else v

    def buffer2msgs(self, arr):
        ret = []
        pos = 0
        arr = arr.rstrip() # TODO: removes the padding, should be ignored or checked?
        arr = bytearray(arr.encode())
        LOGGER.debug(arr)
        LOGGER.debug(codecs.encode(arr, 'hex'))
        LOGGER.debug(len(arr))
        while (pos + 2) <= len(arr):
            _len = (arr[pos] << 8) | arr[pos+ 1]
            LOGGER.debug(_len)
            arr[pos] = 0x4d
            arr[pos + 1] = 0x32
            #LOGGER.debug(arr[pos:pos + _len])
            #LOGGER.debug(codecs.encode(arr[pos:pos + _len], 'hex'))
            #msg = self.buffer2msg(arr[pos:pos + _len])
            msg = self.buffer2msg(arr)
            pos += _len
            ret.append(msg)
        return ret

    def buffer2msg(self, arr):
        ret = {}
        arr_len = len(arr)
        f = io.BytesIO(arr)
        f.seek(2) # Skip first two bytes

        #LOGGER.debug(arr.decode())
        #LOGGER.debug('---')
        LOGGER.debug(arr)
        LOGGER.debug('---')
        LOGGER.debug(codecs.encode(arr, 'hex'))

        def read_bytes(n, buf=f):
            if n == 1:
                return int.from_bytes(buf.read(1), byteorder='big')
            if n == 2:
                ret = struct.unpack('<H', buf.read(2))
            elif n == 4:
                ret = struct.unpack('<I', buf.read(4))
            elif n == 8:
                ret = struct.unpack('<Q', buf.read(8))
            else:
                LOGGER.error('Invalid value for n: ' + str(n))
                return
            return ret[0]

        def num2hex(ccc):
            if ccc < 10:
                return chr(48 + ccc)
            return chr(87 + ccc)

        def idnum2hex(id):
            ret = ''
            for i in range(6):
                x = (id >> (20 - (i * 4))) & 0xf
                if len(ret) == 0 and not x:
                    continue
                ret = ret + num2hex(x)
            if len(ret) == 0:
                ret = '0'
            return ret

        # TODO: read those bytes from the buffer?
        if arr[0] != 0x4d or arr[1] != 0x32:
            LOGGER.error('First char is not 0x4d or second char is not 0x32')
            return ret

        while f.tell() < arr_len:
            id = read_bytes(4)
            LOGGER.debug('Parsing ID: ' + str(id) + ' / ' + hex(id) +
                         ' (mask: ' + str(id & MASK_FTYPE) + ' / ' + hex(id & MASK_FTYPE) + ')')
            if (id & MASK_FTYPE) == FT_BOOL:
                ret['b' + idnum2hex(id)] = 1 if (id & FS_SHORT) else 0
            elif (id & MASK_FTYPE) == FT_U32:
                if id & FS_SHORT:
                    ret['u' + idnum2hex(id)] = read_bytes(1)
                else:
                    ret['u' + idnum2hex(id)] = read_bytes(4)
            elif (id & MASK_FTYPE) == FT_U64:
                ret['q' + idnum2hex(id)] = read_bytes(8)
            elif (id & MASK_FTYPE) == FT_ADDR6:
                a = []
                for i in range(16):
                    a[i] = read_bytes(1)
                ret['a' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_STRING:
                _len = read_bytes(1)
                print('string parsing len: ' + str(_len))
                # TODO: fix not ignore
                #if not (id & FS_SHORT):
                #    _len |= read_bytes(1) << 8
                print('string parsing len 2: ' + str(_len))
                s = ''
                for i in range(_len):
                    print('reading string byte')
                    s += chr(read_bytes(1))
                print('the idnum stuff')
                print(idnum2hex(id))
                ret['s' + idnum2hex(id)] = s
            elif (id & MASK_FTYPE) == FT_RAW:
                _len = read_bytes(1)
                if not (id & FS_SHORT):
                    _len |= read_bytes(1) << 8
                a = []
                for i in range(_len):
                    a[i] = read_bytes(1)
                ret['r' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_MESSAGE:
                _len = read_bytes(1)
                if not (id & FS_SHORT):
                    _len |= read_bytes(1) << 8
                pos = f.tell() # TODO: is that correct here?
                ret['m' + idnum2hex(id)] = self.buffer2msg(arr[pos:pos + _len])
                pos += _len
            elif (id & MASK_FTYPE) == FT_BOOL_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    a[i] = True if read_bytes(1) else False
                ret['B' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_U32_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    a[i] = read_bytes(4)
                ret['U' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_U64_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    a[i] = read_bytes(8)
                ret['Q' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_ADDR6_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    x =[]
                    for k in range(16):
                        x[k] = read_bytes(1)
                    a[i] = x
                ret['A' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_STRING_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    x = ''
                    xlen = read_bytes(2)
                    for k in range(xlen):
                        x += chr(read_bytes(1))
                    a[i] = x
                ret['S' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_RAW_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    x =[]
                    xlen = read_bytes(2)
                    for k in range(xlen):
                        x[k] = read_bytes(1)
                    a[i] = x
                ret['R' + idnum2hex(id)] = a
            elif (id & MASK_FTYPE) == FT_MESSAGE_ARRAY:
                _len = read_bytes(2)
                a = []
                for i in range(_len):
                    xlen = read_bytes(2)
                    pos = f.tell() # TODO: is that correct here?
                    a[i] = self.buffer2msg(arr[pos:pos + xlen])
                    pos += xlen
                ret['M' + idnum2hex(id)] = a
            else:
                LOGGER.warning('Invalid message type: ' + str(id & MASK_FTYPE) + ' / ' + hex(id & MASK_FTYPE))
        return ret


if __name__ == "__main__":
    import sys
    import requests

    if not len(sys.argv) is 4:
        print('Usage: {} host username password'.format(sys.argv[0]))
        sys.exit()

    def dev_get_challenge(host):
        r = requests.post('http://{}/jsproxy'.format(host), stream=True)
        return r.raw.read()

    def dev_send_response(host, resp):
        headers = {'Content-Type': 'text/plain;charset=UTF-8'}
        return requests.post('http://{}/jsproxy'.format(host),
                             data=resp,
                             headers=headers,
                             stream=True)

    s = Session(sys.argv[2], sys.argv[3])
    auth_chal = dev_get_challenge(sys.argv[1])
    s.make_response(auth_chal)
    response = dev_send_response(sys.argv[1], s.response)
    plaintext = s.decrypt(response.raw.read())
    print('First response:', plaintext)
    request = "{Uff0001:[120],uff0007:5}"
    encrypted = s.encrypt(request)
    print('Sending:', request)
    response = dev_send_response(sys.argv[1], encrypted)
    response = response.raw.read()
    plaintext = s.decrypt(response)
    print('Second response:', plaintext)
