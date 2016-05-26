#!/usr/bin/env python3
import argparse
import logging
import sys

from libfixy import WebFigProxy

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
ARGS = argparse.ArgumentParser(description="WebFixy decryption proxy for RouterOS WebFig sessions")
ARGS.add_argument(
    '-H', '--host', default='127.0.0.1',
    help='Host to listen [default: %(default)s]')
ARGS.add_argument(
    '-p', '--port', type=int, default=8080,
    help='Port to listen [default: %(default)d]')
ARGS.add_argument(
    '--target',
    help='Host to connect [default: %(default)s]')
ARGS.add_argument(
    '--target-port', type=int, default=80,
    help='Port to connect [default: %(default)d]')
ARGS.add_argument(
    '--user', default='admin',
    help='WebFig username [default: %(default)s]')
ARGS.add_argument(
    '--password', default='',
    help='WebFig password [default: %(default)s]')
ARGS.add_argument(
    '-v', '--verbose', action='count', dest='level',
    default=2, help='Verbose logging (repeat for more verbose)')
ARGS.add_argument(
    '-q', '--quiet', action='store_const', const=0, dest='level',
    default=2, help='Only log errors')


@asyncio.coroutine
def init_proxy(host, port, user, password, target, loop):
    app = WebFigProxy(
        user=user,
        password=password,
        target=target,
        loop=loop)
    handler = app.make_handler(access_log=None)
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
        init_proxy(
            args.host,
            args.port,
            args.user,
            args.password,
            (args.target, args.target_port), loop))
    try:
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        loop.run_until_complete(handler.finish_connections())
    finally:
        loop.close()


if __name__ == '__main__':
    main()