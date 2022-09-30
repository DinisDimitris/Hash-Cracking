import hashlib
from itertools import permutations

chars = 'abcdefghijklmnopqrstuvwxyz0123456789'

secret = '594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06'

cracked = False

h = hashlib.new('sha256')

def words(letters):
    for n in range(1, len(letters)+1):
        yield from map(''.join, permutations(letters, n))

possible_words = words(chars)

for word in possible_words:
    h.update(str.encode(word))
    hash = h.hexdigest()
    if (hash == secret):
        cracked = True
        break
        

print(cracked)

