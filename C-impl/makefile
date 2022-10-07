all: bruteforce dictcracker

CC=gcc
CFLAGS=-I.

bruteforce: sha256/sha256.o BruteForceHashCracking.o 
			$(CC) -o bruteforce BruteForceHashCracking.o sha256/sha256.o

dictcracker: sha256/sha256.o DictHashCracker.o 
	$(CC) -o dictcracker DictHashCracker.o sha256/sha256.o
