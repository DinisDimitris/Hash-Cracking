import hashlib

class SaltedDictHashCracker():

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
        
        raise Exception('Hash has not been found in the hash dictionary.', hash)

    def AttemptBruteForce(self,hash, salt):
        lookupAttempt = self.LookupHash(hash) 

        if lookupAttempt != '':
            return lookupAttempt
        
        for password in self._passwords:
            h = hashlib.new('sha256')
            encoded = password.encode() + salt.encode() 
            h.update(encoded)
            hashedPw = h.hexdigest()
            if (hash == hashedPw):
                print('Password for hash: ' + hash +  ' is: ' + password)
                self._hashDict[hash] = password
                return
        
        print ('Could not find password for hash: ' + hash)



        