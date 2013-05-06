'''
Copyright (C) 2013 Charles Robert McCreary, Jr.
'''
import Crypto
import Crypto.Random
import base64
import hashlib
import hmac

SIG_SIZE = hashlib.md5('It will be 16 bytes').digest_size

class AuthenticationError(Exception): pass

def pad_data(data):
    # return data if no padding is required
    if len(data) % 16 == 0:
        return data
    # subtract one byte that should be the 0x80
    # if 0 bytes of padding are required, it means only
    # a single 0x80 is required.

    padding_required = 15 - (len(data) % 16)
    data = '{0}\x80'.format(data)
    data = '{0}{1}'.format(data, '\x00' * padding_required)
    return data

def unpad_data(data):
    if not data:
        return data
    data = data.rstrip('\x00')
    if data[-1] == '\x80':
        return data[:-1]
    else:
        return data

def encrypt(key, data):
    iv = Crypto.Random.OSRNG.posix.new().read(16)
    aes = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC,iv)
    sig = hashlib.md5(data).digest()
    data = pad_data(data+sig)
    ct = aes.encrypt(data)
    ct = iv + ct
    return base64.urlsafe_b64encode(ct)

def decrypt(key, data):
    data = base64.urlsafe_b64decode(data)
    iv = data[:16]
    data = data[16:]
    aes = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC,iv)
    data = unpad_data(aes.decrypt(data))
    sig = data[-SIG_SIZE:]
    data = data[:-SIG_SIZE]
    if hashlib.md5(data).digest() != sig:
       raise AuthenticationError("message authentication failed")
    return data

if __name__ == "__main__":
    key = 'secret'
    key = hashlib.sha256(key).digest()
    encrypted_route = encrypt(key,'Client Name')
    print(encrypted_route)
    pt = decrypt(key,encrypted_route)
    print(pt)
    key = 'abcd'
    key = hashlib.sha256(key).digest()
    try:
        pt = decrypt(key,encrypted_route)
    except AuthenticationError:
        print('Sorry! Wrong key!')

