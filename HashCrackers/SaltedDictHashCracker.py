import hashlib

class SaltedDictHashCracker():

    _hashDict = {}
    _passwords = []

    def __init__(self, hashes, passwords):
        for hash in hashes:
            self._hashDict.update({hash : ''})

        self._passwords = passwords

    def LookupSaltedHash(self,hash):
        for hashKey in self._hashDict:
            if (hash == hashKey):
                if (self._hashDict[hashKey] != ''):
                    print('Password for hash: ' + hash +  ' is: ' + self._hashDict[hashKey][0])
                    return self._hashDict[hashKey]
            
        
        raise Exception('Hash has not been found in the hash dictionary.', hash)

    def StorePasswordWithSalt(self, salt):
        for password in self._passwords:
            h = hashlib.new('sha256')
            encoded = password.encode() + salt.encode() 
            h.update(encoded)
            hashedPw = h.hexdigest()

            self._hashDict[hashedPw] = [password, salt]



        