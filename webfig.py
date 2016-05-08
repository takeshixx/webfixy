# -*- coding: utf-8 -*-
from passlib.utils import des
import hashlib
import struct
import codecs

# dev
import requests

USER = 'admin'
PASS = 'AAAA'
HOST = '172.22.11.180'
CRLF = '\r\n'

"""
* Determine initial request:
        * POST with content-length=0
"""


def dev_get_challenge():
    r = requests.post('http://{}/jsproxy'.format(HOST),stream=True)
    return r.raw.read()


def dev_send_response(resp):
    cookie = {'username': USER}
    headers = {'Content-Type': 'text/plain;charset=UTF-8'}
    return requests.post('http://{}/jsproxy'.format(HOST),
                         data=resp,
                         cookies=cookie,
                         headers=headers,
                         stream=True)


class MsChapV2:
    '''MS-CHAP-V2 challenge-response implementation

    https://tools.ietf.org/html/rfc2759
    '''
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
        password = password.encode('utf-16')[2:]
        md4 = hashlib.new('md4')
        md4.update(password)
        return md4.digest()

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
    '''
    RC4 implementation for WebFig
    '''
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

    def decrypt(self, data):
        _data = codecs.decode(data, 'utf8')[8:]
        data = b''
        for i in _data:
            data += struct.pack('B', ord(i) & 0xff)
        o = []
        for i in data:
            o.append(chr((i & 0xff) ^ self.gen()))
        return ''.join(o)


class Session:
    '''
    WebFig session implementation
    '''
    # The hardcoded peer challenge from the original code (!@#$%^&*()_+:3|~)
    peerchal = b'\x21\x40\x23\x24\x25\x5e\x26\x2a\x28\x29\x5f\x2b\x3a\x33\x7c\x7e'
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.mschap = MsChapV2()
        self.rxseq = 0
        self.rxenc = RC4()
        self.txseq = 0
        self.txenc = RC4()
        self.id = None
        self.padding= '        '

    @staticmethod
    def canonicalize_bytes(s):
        '''
        This function canonicalize bytes that will be sent to the server.
        The implementation mimics the original implementation in order
        to generate proper byte sequences.

        :param s: Bytes that should be encoded
        :return: Same bytes that will be generated by the original code
        '''
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
        '''
        Pack bytes received from webfig in order use them for calculations.

        :param s:
        :return:
        '''
        o = b''
        for i in s:
            o += struct.pack('B', ord(i) & 0xff)
        return o

    @staticmethod
    def unpack_bytes(s):
        '''
        Unpack bytes for sending to webfig.

        :param s:
        :return:
        '''
        o = b''
        for i in s:
            i = bytes(chr(i), 'utf8')
            o += struct.pack('{}s'.format(len(i)), i)
        return o

    def make_response(self, response, username=None, password=None):
        '''
        Generate a MS-CHAP-V2 authentication response.

        :param response: Initial response from the server (contains server challenge)
        :param username: Username
        :param password: Password
        :return: Returns the complete message that should be sent back to the server
        '''
        if username:
            self.username = username
        if password:
            self.password = password

        # Generate the MS-CHAP-V2 response for authentication
        response = self.pack_bytes(codecs.decode(response, 'utf8'))
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
        return ret

    def decrypt(self, data):
        if len(data) < 8 + 8:
            return
        self.rxseq += len(data) - 8
        return self.rxenc.decrypt(data)

    def encrypt(self, data):
        self.txseq += len(data) + 8
        o = b''
        o += self.canonicalize_bytes(struct.pack('!I', self.id))
        o += self.canonicalize_bytes(struct.pack('!I', 1))
        o += self.txenc.encrypt(data)
        o += self.txenc.encrypt(self.padding)
        return o

    def encrypt_uri(self, uri):
        # TODO: implement
        pass


if __name__ == "__main__":
    s = Session(USER, PASS)

    challenge = dev_get_challenge()
    #challenge = open('/tmp/chal.ro', 'rb').read()

    resp = s.make_response(challenge)

    re = dev_send_response(resp)
    re = re.raw.read()

    #re = open('/tmp/encrypted.ro', 'rb').read()

    p = s.decrypt(re)
    print(p)

    rr = "{Uff0001:[120],uff0007:5}"
    
    c = s.encrypt(rr)
    print(c)

    re = dev_send_response(c)
    re = re.raw.read()
    print("response")
    print(re)

    print()
    p = s.decrypt(re)
    print(p)
