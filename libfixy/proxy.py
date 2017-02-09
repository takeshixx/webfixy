import codecs
import logging
import struct
import asyncio
import aiohttp
import aiohttp.web

from .webfig import Session
from .deobfuscation import print_message

LOGGER = logging.getLogger(__name__)


class WebFigProxy(aiohttp.web.Application):

    def __init__(self, user, password, target, loop=None):
        super(WebFigProxy, self).__init__()
        self._loop = loop
        self.router.add_route('POST', '/jsproxy', self.jsproxy_post)
        self.router.add_route('GET', '/jsproxy', self.jsproxy_get)
        self.router.add_route('GET', '/jsproxy/', self.jsproxy_get)
        self.router.add_route('GET', '/', self.forward_request)
        self.router.add_route('GET', '/{resource}', self.forward_request)
        self.router.add_route('GET', '/{resource}/', self.forward_request)
        self.router.add_route('GET', '/{resource}/{resource2}', self.forward_request)
        self.router.add_route('GET', '/{resource}/{resource2}/', self.forward_request)
        self.session = Session(user, password)
        assert isinstance(target, tuple)
        self.target = target
        self.target_url = 'http://{}:{}'.format(target[0], target[1])

    @asyncio.coroutine
    def jsproxy_get(self, request):
        """Handle GET requests to jsproxy, decoding encrypted query strings."""
        loop = asyncio.get_event_loop()
        client = aiohttp.ClientSession(loop=loop)
        p, k = yield from self.session.tx_decrypt_uri(request.query_string)
        LOGGER.info('*** SEND_PLAINTEXT_URL: {}'.format(p))
        resp = yield from client.get(self.target_url + request.path)
        try:
            data = yield from resp.read()
        finally:
            yield from resp.release()

        headers = dict()
        for k, v in resp.headers.items():
            if k == 'CONTENT-ENCODING':
                continue
            headers[k] = v
        yield from client.close()
        return aiohttp.web.Response(status=resp.status, headers=headers, body=data)

    @asyncio.coroutine
    def jsproxy_post(self, request):
        """Handle POST requests to jsproxy."""
        loop = asyncio.get_event_loop()
        client = aiohttp.ClientSession(loop=loop)
        try:
            req_body = yield from request.read()
        finally:
            yield from request.release()

        if len(req_body) and self.session.is_authenticated():
            p, k = yield from self.session.tx_decrypt(req_body)
            if not p or not k or not '{' in p or not '}' in p:
                LOGGER.info('COULD NOT DECRYPT')
                LOGGER.info('CIPHER: {}'.format(req_body))
                LOGGER.info('PLAIN: {}'.format(p))
            else:
                LOGGER.info('>>>>>>>>>>>>>>>>>>>>\n{}\n>>>>>>>>>>>>>>>>>>>>'.format(p))
                LOGGER.info('>>>>>>>>>>>>>>>>>>>>\n{}\n>>>>>>>>>>>>>>>>>>>>'.format(print_message(p)))
                enc = self.session.encrypt_with_key(p, k)
                seqid = codecs.decode(req_body)[:8]
                id = struct.unpack('!I', self.session.pack_bytes(seqid)[:4])[0]
                seq = struct.unpack('!I', self.session.pack_bytes(seqid)[4:8])[0]
                LOGGER.debug("TX_ID: ", id)
                LOGGER.debug("TX_SEQ: ", seq)
                LOGGER.debug("SELF TX_SEQ: ", self.session.txseq)
                seqid = bytes(seqid, 'utf8')
                enc = seqid + enc
                if req_body == enc:
                    LOGGER.debug('+++ ENCRYPTION IS THE SAME')
                    req_body = enc
                else:
                    LOGGER.info('!!! ENCRYPTION IS __NOT__ THE SAME')

        resp = yield from client.post(
            '{}/jsproxy'.format(self.target_url), data=req_body)

        try:
            resp_body = yield from resp.read()
        finally:
            yield from resp.release()

        if resp.status is 200:
            if not len(req_body) and len(resp_body):
                self.session.make_response(resp_body)

            elif len(req_body) and len(resp_body) and not self.session.is_authenticated():
                if not self.session.response == req_body:
                    LOGGER.error('Authentication response is not the same')
                LOGGER.info('Authentication successful')
                self.session.set_authenticated()

            if resp.headers['CONTENT-TYPE'] == 'text/plain' and self.session.is_authenticated():
                p, k = self.session.rx_decrypt(resp_body)
                self.session.rx_dequeue()
                if not p or not k or not '{' in p or not '}' in p:
                    LOGGER.info('\n\n\n\n\n******** INVALID RECEIVE PLAINTEXT!!\n\n\n{}\n\n\n'.format(p))
                else:
                    LOGGER.info('<<<<<<<<<<<<<<<<<<<<\n{}\n<<<<<<<<<<<<<<<<<<<<'.format(p))
                    LOGGER.info('<<<<<<<<<<<<<<<<<<<<\n{}\n<<<<<<<<<<<<<<<<<<<<'.format(print_message(p)))
        else:
            LOGGER.info('STATUS IS NOT 200: {}'.format(resp.status))

        headers = dict()
        for k, v in resp.headers.items():
            if k == 'CONTENT-ENCODING':
                continue
            headers[k] = v
        yield from client.close()
        return aiohttp.web.Response(status=resp.status, headers=headers, body=resp_body)

    @asyncio.coroutine
    def forward_request(self, request):
        """Handle any other requests."""
        loop = asyncio.get_event_loop()
        client = aiohttp.ClientSession(loop=loop)
        resp = yield from client.request(
                request.method,
                self.target_url + request.path)
        try:
            data = yield from resp.read()
        finally:
            yield from resp.release()

        headers = dict()
        for k, v in resp.headers.items():
            if k.lower() == 'content-encoding':
                continue
            headers[k] = v

        yield from client.close()
        return aiohttp.web.Response(status=resp.status, headers=headers, body=data)
