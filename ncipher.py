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

if __name__ == '__main__':
    #encrypt 2 files
    out = []
    iv = Random.get_random_bytes(16)
    inputs = [('a','keya'),('b','keyb')]
    streams = list((StreamCipher(KDF.PBKDF2(p, iv), iv), open(f,'rb')) for (f,p) in inputs)

    while True:
        bytes_list = []
        to_delete = []
        for i, (_,f) in enumerate(streams):
            b = f.read(1)
            if not b:
                to_delete.append(i)
            else:
                bytes_list.append(ord(b))

        for n,i in enumerate(to_delete):
            del streams[i-n]

        if len(streams) == 0:
            break

        offset = 1
        bytes_tuple = tuple(bytes_list)
        stream_ciphers = tuple(s for (s,_) in streams)
        print(bytes_tuple)
        for streams_tuple in zip(*stream_ciphers):
            if streams_tuple == bytes_tuple:
                break
            offset += 1
        print(offset)
        out.append(offset)

    ciphertext = iv + b''.join(bytify(b) for b in out)
    print('ciphertext:', ciphertext)

    # Decrypt second file
    iv = ciphertext[:16]
    data = list(ciphertext[16:])
    key = KDF.PBKDF2('keyb', iv)
    stream = StreamCipher(key, iv)
    out = []

    while True:
        i = unbytify(data)
        print(i)
        out.append(next(islice(stream, i-1, i)))
        if not len(data):
            break

    print('plaintext:', bytes(out))
