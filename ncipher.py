import struct
from itertools import *
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto import Random

def StreamCipher(key, iv):
    aes = AES.new(key=key, IV=iv, mode=AES.MODE_OFB)
    buf = b''

    while True:
        if len(buf) == 0:
            buf = list(aes.encrypt(b'\x00'*16))
        yield buf.pop(0)

def bytify(i):
    b = []
    while i > 0:
        x = 0x80 if i > 0x7f else 0
        b.append(x | (i & 0x7f))
        i >>= 7
    return bytes(b)

def unbytify(b):
    i = 0
    n = 0
    while True:
        x = b.pop(0)
        i |= (x & 0x7f) << (7*n)
        if not x & 0x80:
            return i
        n += 1

def find_matching_offset(streams, inactive_streams, plaintexts_bytes):
    offset = 1
    for streams_bytes in zip(*streams):
        [next(s) for s in inactive_streams]
        if streams_bytes == plaintexts_bytes:
            return offset
        offset += 1

def encrypt(keys, plaintexts, iv):
    _plaintexts = list(plaintexts)
    streams = tuple(StreamCipher(key, iv) for key in keys)
    active_streams = list(streams)
    inactive_streams = []

    ciphertext = b''

    while True:
        plaintexts_bytes = tuple(d[0] for d in _plaintexts if d)

        filtered_plaintexts = []
        n = 0
        for i, d in enumerate(_plaintexts):
            if d:
                filtered_plaintexts.append(d[1:])
            else:
                inactive_streams.append(active_streams[i-n])
                del active_streams[i-n]
                n+=1
        _plaintexts = filtered_plaintexts

        if not plaintexts_bytes:
            break

        ciphertext += bytify(find_matching_offset(tuple(active_streams), inactive_streams, plaintexts_bytes))

    max_len = max(len(d) for d in plaintexts)
    paddings = [max_len - len(d) for d in plaintexts]
    paddings_struct = [struct.pack('<I', p) for p in paddings]

    for i in range(4):
        ciphertext += bytify(find_matching_offset(streams, [], tuple(p[i] for p in paddings_struct)))

    return ciphertext

def decrypt(key, ciphertext, iv):
    stream = StreamCipher(key, iv)
    plaintext = bytearray()

    _ciphertext = bytearray(ciphertext)

    while True:
        i = unbytify(_ciphertext)
        plaintext.append(next(islice(stream, i-1, i)))
        if not len(_ciphertext):
            break

    plaintext = bytes(plaintext)
    padding = struct.unpack('<I', plaintext[-4:])[0]

    return plaintext[:-padding-4]

if __name__ == '__main__':
    #encrypt 2 files
    plaintexts = [b'123456', b'1234567890']
    keys = [b'\x00'*16, b'\xff'*16]
    ciphertext = encrypt(keys, plaintexts, iv=b'\x00'*16)
    print(ciphertext)

    # Decrypt second file
    plaintext = decrypt(b'\xff'*16, ciphertext, iv=b'\x00'*16)
    print('plaintext:', plaintext)
