import hashlib
from itertools import product

class DictHashCracker(object):

    @staticmethod
    def ReadHashes(path):
        fileObj = open(path, "r")
        content = fileObj.read().splitlines()
        fileObj.close()
        return content

    @staticmethod
    def AttemptBruteForce(hashToBeCracked):
        hashDict = {}
        
