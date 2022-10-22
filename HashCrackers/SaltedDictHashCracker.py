import hashlib

class SaltedDictHashCracker():

    _hashDict = {}

    # store each password with salt, resulting in permutation of each password with each salt
    def __init__(self, passwords, salts):
        for password in passwords:
            for salt in salts:
                h = hashlib.new('sha256')
                encoded = password.encode() + salt.encode() 
                h.update(encoded)
                hashedPw = h.hexdigest()

                self._hashDict[hashedPw] = [password, salt]

    # lookup a salted hash 
    def LookupSaltedHash(self,hash):
        if (self._hashDict[hash] != ''):
            print('Password for hash: ' + hash +  ' is: ' + self._hashDict[hash][0])
        else:
            print('Password for hash: ' + hash +  ' is not present in the dictionary')
        return self._hashDict[hash]



        