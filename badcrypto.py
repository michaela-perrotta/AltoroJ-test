"""FIPS 180-4:
SHA-1
SHA-2: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.

FIPS 202
SHA3-224, SHA3-256, SHA3-384, and SHA3-512
SHAKE128 and SHAKE256."""

#Crypto
import Crypto
from Crypto.Hash import MD2
from Crypto.Hash import MD4
from Crypto.Hash import MD5
from Crypto.Hash import SHA



#Dangerously insecure
hash = MD2.new()
hash = MD4.new()
hash = MD5.new()
hash = SHA.new()

hash = Crypto.Hash.MD2.new()
hash = Crypto.Hash.MD4.new()
hash = Crypto.Hash.MD5.new()
hash = Crypto.Hash.SHA.new()

##hashlib
import hashlib
import os

hashlib.md5(b"text").hexdigest()
hashlib.sha1(b"text").hexdigest()

#Better with a random salt, but not fully random
#MD5 is insufficient for pw as hashing happens too fast even with a random salt
#Further you must remember the salt somewhere and sharing a single salt in an app for all uses
#effectively removes the value a salt grants
password = b"password"
salt = os.urandom(16)
#Clue that this is likely a pw hash is the +
hashlib.md5().update(salt + password)
hashlib.md5().hexdigest()

#Safer way to hash a  password
#Use at least SHA256
#Easiest to use as it stored the random salt with the hash
#Still not ideal
from passlib.hash import sha256_crypt
from passlib.hash import sha1_crypt
from passlib.hash import md5_crypt

#Not ok
password = sha1_crypt.encrypt("password")
password = md5_crypt.encrypt("password")

#Ok
password = sha256_crypt.encrypt("password")
password2 = sha256_crypt.encrypt("password")

#potential password variable names
#password
#passwd
#pwd
#passwrd
#pswd
#pw
#anything hard coded as a string literal
#Case insensitive


print("PW1:%s" %password)
print("PW2:%s"%password2)

print(sha256_crypt.verify(b"password", password))

#Safest better way
#Hash pw, then add a salt to the result and hash the hash
#This gives you a random salt in the first encrypt call, a second salt for the hash+salt part
#and a final hash in the final encrypt call
mysalt=os.urandom(12)

hash = sha256_crypt.encrypt(b"password")
print(hash)

print(sha256_crypt.verify(b"password", hash))

pwd=b'sefrhiloliutzrthgrfsdyv<sef234244567!"234wsdycvhn'

mypass =mysalt+pwd

print(mypass)

hash2   =sha256_crypt.encrypt(mypass, rounds =200000)
hash1= sha256_crypt.encrypt(pwd, rounds=80000, salt_size=16)

print("hash2: ", hash2)
print(sha256_crypt.verify(mypass,hash2))


#Safe - using MD5, SHA1 on a file
#Open is a pretty big clue here that this is a file
print(hashlib.sha1(open('bad.crypto.py', 'rb').read()).hexdigest())
print(hashlib.md5(open('bad.crypto.py', 'rb').read()).hexdigest())


# Larger files example, safe - just hashing a file
BLOCKSIZE = 65536
hasher = hashlib.md5()
with open('bad.crypto.py', 'rb') as afile:
    buf = afile.read(BLOCKSIZE)
    while len(buf) > 0:
        #The fact that this is a buffer (buf) tells us it is likely not a pw
        hasher.update(buf)
        buf = afile.read(BLOCKSIZE)
print(hasher.hexdigest())

import base64
import uuid

password = b'test_password'
salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)


t_sha = hashlib.sha512()
#Not a terrible hash
t_sha.update(password+salt)
hashed_password = base64.urlsafe_b64encode(t_sha.digest())
print(hashed_password)
