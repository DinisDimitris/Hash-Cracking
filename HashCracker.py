import hashlib
from itertools import product

class BruteForceHashCracker(object):

    CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'
    #adjust permutation depth so that memory doesnt blow up if ran locally
    PERMUTATION_DEPTH = 5

    @staticmethod
    def ReadHashes(path):
        fileObj = open(path, "r")
        content = fileObj.read().splitlines()
        fileObj.close()
        return content

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
