import hashlib

class DictHashCracker():

    _hashDict = {}

    def __init__(self, passwords):
        for password in passwords:
            h = hashlib.new('sha256')
            encoded = password.encode()
            h.update(encoded)
            hashedPw = h.hexdigest()
            self._hashDict[hashedPw] = password

    # Lookup a hash by index
    def LookupHash(self,hash):
        if (self._hashDict[hash] != ''):
            print('Password for hash: ' + hash +  ' is: ' + self._hashDict[hash])
        else:
            print('Password for hash: ' + hash +  ' is not present in the dictionary')
        return self._hashDict[hash]



        