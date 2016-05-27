import hashlib
import struct
import codecs
import urllib.parse
import asyncio
from passlib.utils import des
from passlib.hash import nthash


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
        _data = codecs.decode(data)https://github.com/ernw/nmap-scripts
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
    def tx_dequeue(self,):
        data = ''
        while True:
            data = self.txqueue.get(self.txseq)
            if not data:
                yield from asyncio.sleep(1)
                continue
            del self.txqueue[self.txseq]
            break
        return data

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
    def rx_dequeue(self):
        data = ''
        while True:
            data = self.rxqueue.get(self.rxseq)
            if not data:
                break
            del self.rxqueue[self.rxseq]
        if data:
            return self.rx_decrypt(data)


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
