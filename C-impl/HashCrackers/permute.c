#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256/sha256.h"

int printAllKLengthRec(char const* alphabet, char* prefix, char const* password,
                       size_t alphabetLen, size_t passwordLen, size_t k) {
    if (k == 0) {
        printf("%s\n", prefix);
        return (strncmp(prefix, password, passwordLen) == 0);
    }

    int found = 0;
    for (size_t i = 0; i < alphabetLen; ++i) {
        prefix[passwordLen - k] = alphabet[i];
        found = printAllKLengthRec(alphabet, prefix, password, alphabetLen, passwordLen, k - 1);
        if (found) break;
    }

    return found;
}

const int bufsize = 256;

int main() {
    char alphabet[] = "abcd";
    char password[] = "594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06";
    
    int len = 0;
    len = strlen(alphabet);

    /* Use a buffer to avoid messing with malloc() in printAllKLengthRec */
    char prefix[bufsize];
    memset(prefix, '\0', bufsize);

    size_t const alphalen = strlen(alphabet);

    for (int i = 0; i < len; i++){
        printAllKLengthRec(alphabet, prefix, password, alphalen, i, i);
    }
}