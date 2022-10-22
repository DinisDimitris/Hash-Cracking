import hashlib
from itertools import product

class BruteForceHashCracker(object):

    CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'
    #adjust cross product depth so that memory doesnt blow up if ran locally and hash is not found
    CROSS_PROD_DEPTH = 20

    # yield here will return a generator instead of returning a list of CROSS_PROD_DEPTH**len(CHARS)
    @staticmethod
    def words(letters):
        for n in range(0, BruteForceHashCracker.CROSS_PROD_DEPTH):
           yield from map(''.join, product(letters, repeat=n))

    @staticmethod
    def AttemptBruteForce(hashToBeCracked):
        # generate hash for each word, then compare if it matches the hashToBeCracked
        for word in BruteForceHashCracker.words(BruteForceHashCracker.CHARS):
                password = ''.join(word)
                h = hashlib.new('sha256')
                encoded = password.encode()
                h.update(encoded)
                hash = h.hexdigest()
                if (hash == hashToBeCracked):   
                    print("Hash: " + hashToBeCracked +  " has been cracked, password is: " + password)
                    return password

        print('Hash: ' + hashToBeCracked + ' could not be found for cross product depth = ' + str(BruteForceHashCracker.CROSS_PROD_DEPTH))