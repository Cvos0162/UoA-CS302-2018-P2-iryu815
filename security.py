'''
security.py
ALl the encoding, encryption and hashing method required for COMPSYS302 python project.
author : "iryu815"
'''

#import
from Crypto.Cipher import AES
from Crypto.Cipher import XOR
from Crypto.PublicKey import RSA
from Crypto import Random
import binascii
import base64
import urllib2
import hashlib
import bcrypt
import scrypt
import os

#encryption and decryption
def XORencrypt(raw, key):
    cipher = XOR.new(key)
    return binascii.hexlify(cipher.encrypt(raw))

def XORdecrypt(enc, key):
    enc = binascii.unhexlify(enc)
    cipher = XOR.new(key)
    return cipher.decrypt(enc)

def AES256randkeygen():
    return binascii.hexlify(os.urandom(16))

def AES256keygen(password, salt):
    return binascii.hexlify(password, salt)

def AES256encrypt(raw, key):
    raw += ' ' * (16 - len(raw) % 16)
    iv = ' ' * 16
    raw = iv + raw
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(raw))

def AES256decrypt(enc, key):
    enc = binascii.unhexlify(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return cipher.decrypt(enc[16:]).rstrip(' ')

def RSAkeygen(num):
    new = RSA.generate(num, Random.new().read)
    dic = {'public' : '', 'private' : ''}
    public = binascii.hexlify(new.publickey().exportKey('DER'))
    private = binascii.hexlify(new.exportKey('DER'))
    dic['public'] = public
    dic['private'] = private
    return dic

def RSAimportKey(key):
    result = RSA.importKey(binascii.unhexlify(key))
    return result

def RSAencrypt(raw, key):
    cipher = key.publickey()
    return binascii.hexlify(''.join(cipher.encrypt(raw, 128)))

def RSAdecrypt(enc, key):
    enc = binascii.unhexlify(enc)
    return key.decrypt(enc)

#encoding and decoding
def percentEncode(raw):
    return urllib2.quote(raw)

def percentDecode(enc):
    return urllib2.unquote(enc)

def base64Encode(raw):
    return base64.encodestring(raw)

def base64Decode(enc):
    return base64.decodestring(enc)

#hashing
def SHA256hash(message, salt=''):
    return hashlib.sha256((message + salt).encode()).hexdigest()

def SHA512hash(message, salt):
    return hashlib.sha512((message + salt).encode()).hexdigest()

def bcryptHash(message, salt):
    return bcrypt.hashpw(message, salt)

def scryptHash(message, salt):
    return scrypt.hash(message, salt)

#To test all the function above
def test():
    message = 'message = love'
    salt = 'all'
    print 'message: ' + message
    print 'salt: ' + salt
    xorkey = '10010110'
    print 'XOR key: ' + xorkey
    loginkey = '41fb5b5ae4d57c5ee528adb078ac3b2e'
    print 'AES login key: ' + loginkey
    print ''
    xor = XORencrypt(message, xorkey)
    print 'XOR enc: ' + xor
    print 'XOR dec: ' + XORdecrypt(xor, xorkey)
    print ''
    
    aes = AES256encrypt(message, loginkey)
    print 'with login key: ', loginkey
    print 'AES256 enc: ' + aes
    print 'AES256 dec: ' + AES256decrypt(aes, loginkey)
    print ''

    aeskey = AES256randkeygen()
    aes = AES256encrypt(message, aeskey)
    print 'with keygen: ', aeskey
    print 'AES256 enc: ' + aes
    print 'AES256 dec: ' + AES256decrypt(aes, aeskey)
    print ''
    
    key = RSAkeygen(1024)
    print 'RSA1024 pubkey: ', key['public']
    print 'RSA1024 prikey: ', key['private']
    rsa = RSAencrypt(message, RSAimportKey( key['public']))
    print 'RSA1024 pubenc: ', rsa
    print 'RSA1024 pridec: ', RSAdecrypt(rsa, RSAimportKey(key['private']))
    print ''
    key = RSAkeygen(2048)
    print 'RSA2048 pubkey: ', key['public']
    print 'RSA2048 prikey: ', key['private']
    rsa = RSAencrypt(message, RSAimportKey(key['public']))
    print 'RSA2048 enc: ', rsa
    print 'RSA2048 dec: ', RSAdecrypt(rsa, RSAimportKey(key['private']))
    print ''
    per = percentEncode(message)
    print 'Percent enc: ' + per
    print 'Percent dec: ' + percentDecode(per)
    print ''
