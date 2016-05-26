WebFixy
=======

[WebFig](http://wiki.mikrotik.com/wiki/Manual:Webfig) is a web management interface that comes with MikroTik's [RouterOS](http://www.mikrotik.com/software). By default it encrypts HTTP traffic (even without SSL/TLS) by implementing a authentication and encryption scheme similar to PPTP. WebFixy is a web proxy that decrypts WebFig sessions on-the-fly in order to observe the communication between a browser and a RouterOS host. It also supports encryption of payloads, which allows to tamper with traffic. However, currently there are various limitations for tampering.
 
## Compatibility

The proxy functionality is implemented with [aiohttp](https://github.com/KeepSafe/aiohttp) which is based on [asyncio](https://docs.python.org/3/library/asyncio.html). Therefore WebFixy requires at least Python 3.3!

## Usage

The only mandatory argument is `--target` which is the IP address or hostname of the RouterOS system running WebFig:

```
python webfixy.py --target 192.168.0.1
```

This will start the proxy listener on localhost port 8080. In order to start a WebFig session over the browser, just use the listener socket instead of the actual RouterOS host:

```
http://127.0.0.1:8080
```

The proxy will login with the default username `admin` and a empty password. This can be changed by supplying the actual login credentials:

```
python webfixy.py --target 192.168.0.1 --user admin --password supersecret
```