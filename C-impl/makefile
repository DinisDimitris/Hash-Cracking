CC=gcc
CFLAGS=-I.

make: sha256/sha256.o BruteForceHashCracking.o 
	$(CC) -o bruteforce BruteForceHashCracking.o sha256/sha256.o

make: sha256/sha256.o DictHashCracker.o 
	$(CC) -o dictcracker DictHashCracker.o sha256/sha256.o