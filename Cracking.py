from HashCracker import BruteForceHashCracker, HashCracker, DictHashCracker

if __name__ == '__main__':
    hashes = HashCracker.Read('hashes.txt')

    print ('Brute force hash cracker\n ---------------------')
    for hash in hashes:
        BruteForceHashCracker.AttemptBruteForce(hash)

    
    dictHashes = HashCracker.Read('dicthashes.txt')
    passwords = HashCracker.Read('PasswordDictionary.txt')

    print ('\nDictionary attack\n ---------------------')
    dictHashCracker = DictHashCracker(dictHashes, passwords)

    for dictHash in dictHashes:
        dictHashCracker.AttemptBruteForce(dictHash)

    
