#!/usr/bin/env python3
import sys
import logging
import argparse
import aiohttp
import aiohttp.web

import webfig

# asyncio requires at least Python 3.3
if sys.version_info.major < 3 or \
    (sys.version_info.major > 2 and
    sys.version_info.minor < 3):
    print('At least Python version 3.3 is required to run this script!')
    sys.exit(1)

# Python 3.4 ships with asyncio in the standard libraries. Users with Python 3.3
# need to install it, e.g.: pip install asyncio
try:
    import asyncio
except ImportError:
    print('Please install asyncio!')
    sys.exit(1)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

LOGGER = logging.getLogger(__name__)
ARGS = argparse.ArgumentParser(description="Traffic forwarder")
ARGS.add_argument(
    '-H', '--host', default='127.0.0.1',
    help='Host to listen [default: %(default)s]')
ARGS.add_argument(
    '-p', '--port', type=int, default=8080,
    help='Port to listen [default: %(default)d]')
ARGS.add_argument(
    '--target', default='127.0.0.1',
    help='Host to connect [default: %(default)s]')
ARGS.add_argument(
    '--target-port', type=int, default=80,
    help='Port to connect [default: %(default)d]')
ARGS.add_argument(
    '-v', '--verbose', action='count', dest='level',
    default=2, help='Verbose logging (repeat for more verbose)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='Only log errors')


class WebFigProxy(aiohttp.web.Application):

    def __init__(self, target, loop=None):
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
        self.session = webfig.Session(webfig.USER, webfig.PASS)
        assert isinstance(target, tuple)
        self.target = target
        self.target_url = 'http://{}:{}'.format(target[0], target[1])

    @asyncio.coroutine
    def jsproxy_get(self, request):
        """Handle GET requests to jsproxy, decoding encrypted query strings."""
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        p = self.session.tx_decrypt_uri(request.query_string)
        LOGGER.info('*** SEND_PLAINTEXT_URL: {}'.format(p))
        resp = yield from session.get(self.target_url + request.path)
        try:
            data = yield from resp.read()
        finally:
            yield from resp.release()

        headers = dict()
        for k, v in resp.headers.items():
            if k == 'CONTENT-ENCODING':
                continue
            headers[k] = v
        return aiohttp.web.Response(status=resp.status, headers=headers, body=data)

    @asyncio.coroutine
    def jsproxy_post(self, request):
        """Handle POST requests to jsproxy."""
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        try:
            req_body = yield from request.read()
        finally:
            yield from request.release()

        if len(req_body) and self.session.is_authenticated():
            p = self.session.txenc.decrypt(req_body)
            LOGGER.info('*** SEND_PLAINTEXT: {}'.format(p))

        resp = yield from session.post(
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
                    LOGGER.info('***** RESPONSES ARE NOT THE SAME *****')
                LOGGER.info('Authentication successful')
                self.session.set_authenticated()

            if resp.headers['CONTENT-TYPE'] == 'text/plain' and self.session.is_authenticated():
                p = self.session.rxenc.decrypt(resp_body)
                LOGGER.info('*** RECEIVE_PLAINTEXT: {}'.format(p))
        else:
            LOGGER.info('STATUS IS NOT 200: {}'.format(resp.status))

        headers = dict()
        for k, v in resp.headers.items():
            if k == 'CONTENT-ENCODING':
                continue
            headers[k] = v
        return aiohttp.web.Response(status=resp.status, headers=headers, body=resp_body)

    @asyncio.coroutine
    def forward_request(self, request):
        """Handle any other requests."""
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        resp = yield from session.request(
                request.method,
                self.target_url + request.path)
        try:
            data = yield from resp.read()
        finally:
            yield from resp.release()

        headers = dict()
        for k, v in resp.headers.items():
            if k == 'CONTENT-ENCODING':
                continue
            headers[k] = v

        yield from session.close()
        return aiohttp.web.Response(status=resp.status, headers=headers, body=data)


@asyncio.coroutine
def init_proxy(host, port, target, loop):
    app = WebFigProxy(target=target, loop=loop)
    handler = app.make_handler()
    server = yield from loop.create_server(handler, host, port)
    return server, handler


def main():
    args = ARGS.parse_args()
    levels = [logging.ERROR, logging.WARN, logging.INFO, logging.DEBUG]
    if args.level > 2:
        format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'
    else:
        format = '%(message)s'
    logging.basicConfig(level=levels[min(args.level, len(levels)-1)], format=format)
    loop = asyncio.get_event_loop()
    server, handler = loop.run_until_complete(
        init_proxy(args.host, args.port, (args.target, args.target_port), loop))
    try:
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        loop.run_until_complete(handler.finish_connections())
    finally:
        loop.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())