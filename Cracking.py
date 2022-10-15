from HashCrackers.BruteForceHashCracker import BruteForceHashCracker
from HashCrackers.DictHashCracker import DictHashCracker
from HashCrackers.SaltedDictHashCracker import SaltedDictHashCracker
import time

def Read(path):
        fileObj = open(path, "r")
        content = fileObj.read().splitlines()
        fileObj.close()
        return content

if __name__ == '__main__':
    hashes = Read('hashes/hashes.txt')

    start = time.time()
    print ('Brute force hash cracker\n ---------------------')
    for hash in hashes:
        BruteForceHashCracker.AttemptBruteForce(hash)
    end = time.time()
    print ("Execution time: {}".format(end - start))

    dictHashes = Read('hashes/dicthashes.txt')
    passwords = Read('hashes/PasswordDictionary.txt')

    start = time.time()
    print ('\nDictionary attack\n ---------------------')
    dictHashCracker = DictHashCracker(dictHashes, passwords)
    

    for dictHash in dictHashes:
        dictHashCracker.StoreHashes()

    for dictHash in dictHashes:
        dictHashCracker.LookupHash(dictHash)

    end = time.time()
    print ("Execution time: {}".format(end - start))

    print ('\nSalted Dictionary attack\n ---------------------')
    saltedHashes = [('915edb4d39ab6d260e3fb7269f5d9f8cfba3fdc998415298af3e6eb94a82e43e','27fb57e9'),
    ('5ddce1dc316e7914ab6af64ef7c00d8b603fac32381db963d9359c3371a84b3a','b7875b4b'),
    ('7e3b02bacd934245aa0cb3ea4d2b2f993a8681a650e38a63175374c28c4a7d0d','ec13ab35'),
    ('d3136c0cb931acc938de13ed45926eb8764f9ea64af31be479be157480fd3014','29b49fce'),
    ('3a9053a077383d11f5963ef0c66b38c7eb8331cdb03bbdcc0e5055307f67331b','acdabf8a'),
    ('59c05d8d7b6d29279975141f7329cd77a5dc6942b036f9dfd30cbcb52c320cb4','64afe39d'),
    ('c93802a2273a13c2b8378f98dda9f166783cbfce508aeaf570ad0b19a906b4d2','f0919683'),
    ('e6a9713791c2ffeddbf6c6c395add47e1fc02ae1fa47febbbdfb694ed688ba61','081b2451'),
    ('e6ec51a2ef933920ac1e6d3d8ba6ffac77fe94bfb79518b03cd9b94a14e97d3e','defb64a3'),
    ('fbecd00c62b01135f9e588883e80f2710a354c0eb73a33a2c5ab5602cc85f6ad','017bb5b7')]
    
    hashes = [x[0] for x in saltedHashes]

    start = time.time()
    saltedHashCracker = SaltedDictHashCracker(hashes, passwords)
    for saltedDictHash in saltedHashes:
        saltedHashCracker.StorePasswordWithSalt(saltedDictHash[1])

    for saltedDictHash in saltedHashes:
        saltedHashCracker.LookupSaltedHash(saltedDictHash[0])

    end = time.time()
    print ("Execution time: {}".format(end - start))
    

