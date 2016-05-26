import demjson

values = {
    'uff000b': 'policy',
    'sfe0009': 'skin',
    's1': 'user',
    's2': 'manualURL',
    's11': 'arch',
    's15': 'boardname',
    's16': 'version',
    's17': 'board',
    's2c': 'displayname',
    'M1': 'prefs',
    'Uff0001': 'path',
    'Uff0002': '',
    'uff0007': 'cmd',
    'ufe0001': 'safeModeid',
    'u1': 'sqcaps' # uptime?
}

cmds = {
    0xfe0003: '', # newObject
    0xfe0005: '', # newObject
    0xfe0006: 'removeObject',
    0xfe0007: 'moveObjectAfter',
    0xfe0008: 'next',
    0xfe0010: 'fetch',
    0xfe0012: 'subscribe',
    0xfe0013: 'unsubscribe',
    0xfe0014: 'logout',
    0xfe000e: 'safePrefs'
}

errors = {
    0xfe0002: 'feature is not implemented',
    0xfe0003: 'feature is not implemented',
    0xfe0011: 'object doesn\'t exist',
    0xfe0004: 'object doesn\'t exist',
    0xfe0007: 'object already exists',
    0xfe0009: 'not permitted',
    0xfe0012: 'busy',
    0xfe000d: 'timeout'
}

def print_message(msg):
    msg = demjson.decode(msg)
    r = dict()
    for k, v in msg.items():
        if v in list(cmds.keys()) and cmds[v]:
            v = cmds[v]
        if k in values.keys():
            r[values[k]] = v
        else:
            r[k] = v

    return r