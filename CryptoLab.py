''' Server.py
usage: python Server.py
Prints out conversation displaying use of cryptographic functions
Modified by Wilson Turner and Chris Drewry 3/30/15
'''

import sys, json, string, random, pickle

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
import textwrap
import math
import array

# Import socket library
from socket import *

# RFC-3526 based p and g values from the 6144-bit MODP Group 
randomUpperBound = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
randomLowerBound = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# empty strings to store the keys to be used for encryption, decryption, signing, and verifying
userCount = 2


# empty strings to store the keys to be used for encryption, decryption, signing, and verifying
delta = 2**5
n = 2
m = 0

# takes in a message and hashes it using SHA256, it then returns the hash's hexdigest which is its readable digest
def createSHA256Hash(message):
        h = SHA256.new()
        h.update(message)
        return h.hexdigest()

def generateM():
        m = "%x" % int(2**(math.ceil(int(math.log(n * delta, 2)))))
        return m

# HMAC signing method takes in a message and signs it using an agreed upon secret key, the message to be signed, and the hashing algorithm(SHA256) it returns the hexdigest
def signHMAC(secret, message):
        h = HMAC.new(secret, message, SHA256)
        return h.hexdigest()

def lengthMatchHash(message, size):
        hashLength = size / 4
        test = textwrap.wrap(message, hashLength)
        a = xor(test[0], test[1])
        for x in xrange(2, len(test)):
                a = xor(a, test[x])
        return a
                
# http://stackoverflow.com/questions/11119632/bitwise-xor-of-hex-numbers-in-python
def xor(a, b):
        if len(a) > len(b):
                return '%x' % (int(a[:len(b)],16)^int(b,16))
        else:
                return '%x' % (int(a,16)^int(b[:len(a)],16))

def decryptData(ciphertexts, iteration, secretArray):
        decryptKey = 0
        for x in xrange(0,len(secretArray)):
                hmacSignature = signHMAC(secretArray[x], str(iteration))
                partialKey = lengthMatchHash(hmacSignature, len(m) * 4)
                decryptKey += int(partialKey, 16)
        total = "%x" % decryptKey
        key = int(total, 16) % int(m, 16)
        print key

        total = 0;
        print "Totals:"
        print ciphertexts
        for x in xrange(0,len(ciphertexts)):
                total = total + ciphertexts[x] - key
                print total
        total = total % int(m, 16)
        print "Return:"
        return total

# Receives an AES encrypted message and an RSA signed SHA256 hash of a message it then verifies the entegrity and prints the decrypted message
def generateSecret():
        b = random.SystemRandom().randint(randomLowerBound, randomUpperBound)
        hashedSecret = createSHA256Hash(str(b))
        return hashedSecret[0:16]

def encryptData(data, iteration, secretArray):
        encryptKey = 0
        for x in xrange(0,len(secretArray)):
                hmacSignature = signHMAC(secretArray[x], str(iteration))
                partialKey = lengthMatchHash(hmacSignature, len(m) * 4)
                encryptKey += int(partialKey, 16)
        total = "%x" % encryptKey
        key = int(total, 16) % int(m, 16)
        print "Key:"
        print key
        cipherText = (key + data) % int(m, 16)
        return cipherText

#####################################################################################################################################
m = generateM()
# Secret generation
a = []
a.append(generateSecret())
secretCount = 10 * userCount - 1
for x in xrange(0,secretCount):
        a.append(generateSecret())
secretArray = a
print "Secret Array"
print secretArray
print

chunks = [secretArray[x:x+10] for x in xrange(0, len(secretArray), 10)]
random.shuffle(secretArray)
print secretArray
print chunks[0]
print chunks[1]

# user 1
data1 = encryptData(13, 1, chunks[0])
data2 = encryptData(6, 1, chunks[1])
things = [data1, data2]
total = decryptData(things, 1, secretArray)
print total




















# serverPort = 5555
# trustedName = "127.0.0.1"
# trustedPort = 5557
# clientSocket = socket(AF_INET, SOCK_STREAM)
# clientSocket.connect((trustedName, trustedPort))

# clientSocket.send("Agg")
# pickleString = clientSocket.recv(4096)
# secretArray = pickle.loads(pickleString)
# print "Received:"
# print secretArray
# clientSocket.close()

# # Choose SOCK_STREAM, which is TCP
# # This is a welcome socket
# serverSocket = socket(AF_INET, SOCK_STREAM)
# serverSocket.bind(('', serverPort))
# serverSocket.listen(1)
# print "Aggregator is awaiting data..."
# print

# # Wait for connection and create a new socket
# # It blocks here waiting for connection
# m = generateM()
# connectionSocket, addr = serverSocket.accept()
# connectionSocket1, addr = serverSocket.accept()

# user1Data1 = connectionSocket1.recv(4096)
# print "Received:"
# print user1Data1

# user2Data1 = connectionSocket.recv(4096)
# print "Received:"
# print user2Data1

# arrayOfInputs = []
# arrayOfInputs.append(int(user1Data1))
# arrayOfInputs.append(int(user2Data1))
# print "Array:"
# print arrayOfInputs
# decryptData(arrayOfInputs, 1)

# user1Data2 = connectionSocket1.recv(4096)
# print "Received2:"
# print user1Data2
# connectionSocket1.close()

# user2Data2 = connectionSocket.recv(4096)
# print "Received2:"
# print user2Data2
# connectionSocket.close()

# sumData(user1Data2, user2Data2)
#####################################################################################################################################






