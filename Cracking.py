from HashCracker import BruteForceHashCracker

if __name__ == '__main__':
    hashes = BruteForceHashCracker.ReadHashes('hashes.txt')

    for hash in hashes:
        BruteForceHashCracker.AttemptBruteForce(hash)
