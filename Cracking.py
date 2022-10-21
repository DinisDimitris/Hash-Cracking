from HashCrackers.BruteForceHashCracker import BruteForceHashCracker
from HashCrackers.DictHashCracker import DictHashCracker
from HashCrackers.SaltedDictHashCracker import SaltedDictHashCracker
import time

# set to 1 if you wanna save execution times to txt
SAVE_OUT = 1

def Read(path):
        fileObj = open(path, "r")
        content = fileObj.read().splitlines()
        fileObj.close()
        return content

if __name__ == '__main__':
    hashes = Read('hashes/bruteforcehashes.txt')

    start = time.time()
    print ('Brute force hash cracker\n ---------------------')

    longestPwLength = 0
    for hash in hashes:
        pw = BruteForceHashCracker.AttemptBruteForce(hash)
        if (len(pw) > longestPwLength):
            longestPwLength = len(pw)
    end = time.time()

    bruteForceExecTime = end - start

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
    dictAttackTime = end - start

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
    ('fbecd00c62b01135f9e588883e80f2710a354c0eb73a33a2c5ab5602cc85f6ad','017bb5b7'),
    ("8d11a489044177d7a85057d7ba785e431ac2c2a920e458153d064fef4b180a20", "017bb5b7"),
    ("ebff5104dba239061e17f850634273ba0100b0ef9acea88cab71492b2a0c0e50", "081b2451"),
    ("6634a66b7d20c6bc515941e77678b42b129962ec92907906935404bef4c5ed33", "defb64a3"),
    ("c8d8d943b9c32322099fc9fb872e7abc332558d08226e9c125bd6a0e0f9be967", "017bb5b7"),
    ("fa8debb7965f3413e956f6dffe08d21b2c37a2111d3ce7615139302ba2f4bdc0", "017bb5b7"),
    ("fe8d2120756efb18007d798ad129153ce95c47af01f3f7abc692243ba6b34651", "017bb5b7"),
    ("ed90f01fb97ccbbd2658bb8cfabacb599a65d4918a730abf379f4f5427d2be34", "081b2451"),
    ("71b018727d5a8b5d9914552e711efd6c757428742c8753056a945c08b9fa254f", "defb64a3"),
    ("8c5b87360abaccea310b4d669730217711d4930c59c6c2adbcd5e769a50eadcd", "017bb5b7"),
    ("f04cb080072c7d4356abba5795fd43f6f0d75d8227f6abdfb322c27c3b7718e7", "017bb5b7")]
    
    hashes = [x[0] for x in saltedHashes]

    start = time.time()
    saltedHashCracker = SaltedDictHashCracker(hashes, passwords)
    for saltedDictHash in saltedHashes:
        saltedHashCracker.StorePasswordWithSalt(saltedDictHash[1])

    for saltedDictHash in saltedHashes:
        saltedHashCracker.LookupSaltedHash(saltedDictHash[0])

    end = time.time()
    saltDictAttackTime = end - start

    #save execution time
    print ("Execution time for brute force with max password size: {0} : {1} ms ".format(longestPwLength, bruteForceExecTime))
    print ("Execution time for dict attack with {0} hashes: {1} ms".format(len(dictHashes),dictAttackTime))
    print ("Execution time for salted dict attack with {0} hashes: {1} ms".format(len (saltedHashes), saltDictAttackTime))

    if (SAVE_OUT):
        f = open('analysis/pytimings/bruteforcecrack.txt', 'a')
        f.write('{0}:{1}\n'.format(longestPwLength, bruteForceExecTime))
        f.close()
        
        y = open('analysis/pytimings/dictcrack.txt', 'a')
        y.write('{0}:{1}\n'.format(len(dictHashes),dictAttackTime))
        y.close()
        
        file_object = open('analysis/pytimings/salteddictcrack.txt', 'a')
        file_object.write('{0}:{1}\n'.format(len (saltedHashes), saltDictAttackTime))
        file_object.close()
    

