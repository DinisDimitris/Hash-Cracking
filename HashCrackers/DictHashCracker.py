import hashlib

class DictHashCracker():

    _hashDict = {}
    _passwords = []

    def __init__(self, hashes, passwords):
        for hash in hashes:
            self._hashDict.update({hash : ''})

        self._passwords = passwords

    def LookupHash(self,hash):
        print('Password for hash: ' + hash +  ' is: ' + self._hashDict[hash])
        return self._hashDict[hash]
        

    def StoreHashes(self):
        for password in self._passwords:
            h = hashlib.new('sha256')
            encoded = password.encode()
            h.update(encoded)
            hashedPw = h.hexdigest()
            self._hashDict[hashedPw] = password



        