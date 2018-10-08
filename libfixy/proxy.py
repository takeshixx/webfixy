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
        # TODO: make regex work on URL path
        self.router.add_route('GET', r'/webfig/{script:master-min-\w+.js}', self.rewrite_script)
        self.router.add_route('GET', '/webfig/master-min-74bfa7876bcb.js', self.rewrite_script)
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

        #if self.session.is_authenticated() and request.headers['CONTENT-TYPE'] == 'msg':
        if request.headers['CONTENT-TYPE'] == 'msg':
            # Here we are already authenticated and ready to decrypt.
            p, k = yield from self.session.tx_decrypt_msg(req_body)
            LOGGER.debug('Received msg from CLIENT')
            LOGGER.info(req_body)
            LOGGER.info(p)
            LOGGER.info(codecs.encode(p.encode(), 'hex'))
            LOGGER.info('---')
            #yield from self.session.tx_dequeue()
            # if not p or not k or not '{' in p or not '}' in p:
            #     LOGGER.info('COULD NOT DECRYPT')
            #     LOGGER.info('CIPHER: {}'.format(req_body))
            #     LOGGER.info('PLAIN: {}'.format(p))
            # else:
            if p and k:
                #LOGGER.info('>>>>>>>>>>>>>>>>>>>>\n{}\n>>>>>>>>>>>>>>>>>>>>'.format(p))
                #LOGGER.debug('parsed stuff 1')
                #parsed_msg = self.session.buffer2msg(p)
                parsed_msg = self.session.buffer2msgs(p)
                LOGGER.debug('Parsed message: ' + str(parsed_msg))
                #LOGGER.info('>>>>>>>>>>>>>>>>>>>>\n{}\n>>>>>>>>>>>>>>>>>>>>'.format(print_message(p)))
                enc = self.session.encrypt_with_key(p, k)
                #seqid = codecs.decode(req_body)[:8]
                #seqid = req_body[:8]
                #id = struct.unpack('!I', self.session.pack_bytes(seqid)[:4])[0]
                #seq = struct.unpack('!I', self.session.pack_bytes(seqid)[4:8])[0]
                #LOGGER.debug("TX_ID: ", id)
                #LOGGER.debug("TX_SEQ: ", seq)
                #LOGGER.debug("SELF TX_SEQ: ", self.session.txseq)
                #seqid = bytes(seqid, 'utf8')
                #enc = seqid + enc
                #if req_body == enc:
                #    LOGGER.debug('+++ ENCRYPTION IS THE SAME')
                #    req_body = enc
                #else:
                #    LOGGER.info('!!! ENCRYPTION IS __NOT__ THE SAME')
            else:
                LOGGER.warning('Could not decrypt message')

        # Make sure to set the original requests' headers
        resp = yield from client.post(
            '{}/jsproxy'.format(self.target_url), data=req_body, headers=request.headers)

        try:
            resp_body = yield from resp.read()
        finally:
            yield from resp.release()

        if resp.status is 200:
            if len(resp_body) and resp.headers['CONTENT-TYPE'] == 'text/plain':
                # We got the pub key response
                self.session.auth_in_progress = True
                # TODO: implement check for WebFig version
                if True:
                    #self.session.make_response_curve25519()
                    self.session.key_exchange_curve25519(resp_body)
            elif len(resp_body) and resp.headers['CONTENT-TYPE'] == 'msg' and self.session.auth_in_progress:
                LOGGER.info('Authentication successful')
                self.session.set_authenticated()
                self.session.auth_in_progress = False

            if resp.headers['CONTENT-TYPE'] == 'msg' and self.session.is_authenticated():
                # We are past authentication
                LOGGER.debug('Received msg from SERVER')
                LOGGER.debug(resp_body)
                LOGGER.debug(codecs.encode(resp_body, 'hex'))
                LOGGER.debug('---')
                p, k = yield from self.session.rx_decrypt_msg(resp_body)
                yield from self.session.rx_dequeue(msg=True)
                LOGGER.debug(p)
                LOGGER.debug(codecs.encode(p.encode(), 'hex'))
                LOGGER.debug('---')
                if not p or not k:
                    LOGGER.info('\n\n\n\n\n******** INVALID RECEIVE PLAINTEXT!!\n\n\n{}\n\n\n'.format(p))
                else:
                    #LOGGER.info('<<<<<<<<<<<<<<<<<<<<\n{}\n<<<<<<<<<<<<<<<<<<<<'.format(p))
                    #LOGGER.debug('parsed stuff 2')
                    #parsed_msg = self.session.buffer2msg(p)
                    parsed_msg = self.session.buffer2msgs(p)
                    LOGGER.debug('Parsed message: ' + str(parsed_msg))
                    #LOGGER.info('<<<<<<<<<<<<<<<<<<<<\n{}\n<<<<<<<<<<<<<<<<<<<<'.format(print_message(p)))
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
        """Handle any other requests that are not
        modified."""
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

    @asyncio.coroutine
    def rewrite_script(self, request):
        """Rewrite whatever in the main script file."""
        LOGGER.debug('Rewriting script')

        loop = asyncio.get_event_loop()
        client = aiohttp.ClientSession(loop=loop)
        resp = yield from client.request(
                request.method,
                self.target_url + request.path)
        try:
            data = yield from resp.read()
        finally:
            yield from resp.release()

        key = b'['
        key += b'\'A\',' * 31
        key += b'\'A\']'
        data = data.replace(b'this.privKey=key', b'this.privKey=' + key)

        headers = dict()
        for k, v in resp.headers.items():
            if k.lower() == 'content-encoding':
                continue
            if k.lower() == 'content-length':
                headers[k] = str(len(data))
            else:
                # Use the original header
                # without modification.
                headers[k] = v

        yield from client.close()


        return aiohttp.web.Response(status=resp.status, headers=headers, body=data)
