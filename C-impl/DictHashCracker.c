#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256/sha256.h"

void PrintHex(BYTE buf[SHA256_BLOCK_SIZE])
{
    printf("Encoding: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        if (i > 0)
            printf("");
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int CheckHash(BYTE buf[SHA256_BLOCK_SIZE], size_t length, char const *password)
{
    char *buf2 = malloc(length * 2);

    char *ptr = buf2;

    int i;
    for (i = 0; i < length; i++)
    {
        ptr += sprintf(ptr, "%02x", buf[i]);
    }

    if (strcmp(buf2, password) == 0){
        free(buf2);
        return 1;
    }

    free(buf2);
    return 0;
}

int kWordsRecursive(char const *alphabet, char *prefix, char const *password,
                       size_t alphabetLen, size_t passwordLen, size_t k)
{
    if (k == 0)
    {
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;

        sha256_init(&ctx);
        sha256_update(&ctx, prefix, strlen(prefix));
        sha256_final(&ctx, buf);

        int isMatch = CheckHash(buf, sizeof(buf), password);

        if (isMatch == 1)
        {
            printf("Hash: %s ", password);
            printf("Has been cracked, password is: %s\n", prefix);
            return 1;
        }

        return 0;
    }

    int found = 0;
    for (size_t i = 0; i < alphabetLen; ++i)
    {
        prefix[passwordLen - k] = alphabet[i];
        found = kWordsRecursive(alphabet, prefix, password, alphabetLen, passwordLen, k - 1);
        if (found)
            break;
    }

    return found;
}


int main()
{
    
}