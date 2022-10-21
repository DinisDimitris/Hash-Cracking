# Hash-Cracking
A repository containing hash-cracking algorithms for sha256 hashes in python and c 


For the python implementation, run python Cracking.py which is located in the root dir. It will run all 3 approaches

The hashlib-sha256 library has been used for hashing.

For the C implementation, I have included a make file which will compile all 3 approaches. I did not want to chain any headers as gcc was already taking a param for sha256, therefore I kept all 3 executables separate. 

To run the C implementation, cd into C-impl/ and run make. This will create a executable for each task, namely:
-bruteforce\n
-dictcracker
-saltcracker
Each of these can be run as any executable (eg ./bruteforce)

If you wanna use the gnu c compiler, a link with the sha256 file will need to be established as following:
gcc -o {out_file} BruteForceHashCracking.o sha256/sha256.o

If debugging is desired, you will have to add the debugging symbols when compiling:
gcc -g {out_file} BruteForceHashCracking.o sha256/sha256.o

The C implementation uses little endian byte order sha256, which can be found here:https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
It also uses uthash for dictionaries: https://troydhanson.github.io/uthash/
