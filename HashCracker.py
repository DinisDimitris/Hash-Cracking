import hashlib
from itertools import product

class HashCracker(object):

    @staticmethod
    def Read(path):
        fileObj = open(path, "r")
        content = fileObj.read().splitlines()
        fileObj.close()
        return content

        
class BruteForceHashCracker(object):

    CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'
    #adjust permutation depth so that memory doesnt blow up if ran locally
    PERMUTATION_DEPTH = 5

    @staticmethod
    def words(letters):
        for n in range(1, BruteForceHashCracker.PERMUTATION_DEPTH):
           yield from map(''.join, product(letters, repeat=n))

    @staticmethod
    def AttemptBruteForce(hashToBeCracked):
        for word in BruteForceHashCracker.words(BruteForceHashCracker.CHARS):
                password = ''.join(word)
                h = hashlib.new('sha256')
                encoded = password.encode()
                h.update(encoded)
                hash = h.hexdigest()
                if (hash == hashToBeCracked):   
                    print("Hash: " + hashToBeCracked +  " has been cracked, password is: " + password)
                    return

        print('Hash: ' + hashToBeCracked + ' could not be found for permutation depth = ' + str(BruteForceHashCracker.PERMUTATION_DEPTH))

class DictHashCracker():

    _hashDict = {}
    _passwords = []

    def __init__(self, hashes, passwords):
        for hash in hashes:
            self._hashDict.update({hash : ''})

        self._passwords = passwords

    def LookupHash(self,hash):
        for hashKey in self._hashDict:
            if (hash == hashKey):
                if (self._hashDict[hashKey] != ''):
                    return self._hashDict[hashKey]
                
                return ''
        
        raise Exception('Hash: ' + hash + ' has not been found in the hash dictionary.')

    def AttemptBruteForce(self,hash):
        lookupAttempt = self.LookupHash(hash) 

        if  lookupAttempt != '':
            return lookupAttempt
        
        for password in self._passwords:

            h = hashlib.new('sha256')
            encoded = password.encode()
            h.update(encoded)
            hashedPw = h.hexdigest()
            if (hash == hashedPw):
                print('Password for hash: ' + hash +  ' is: ' + password)
                self._hashDict[hash] = password
                return
        
        print ('Could not find password for hash: ' + hash)



        