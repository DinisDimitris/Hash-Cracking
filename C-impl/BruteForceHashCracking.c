#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sha256/sha256.h"

const int BUFSIZE = 256;

/* set to 1 if you wanna save exec time to txt
first column is for the password list length and second for their respective time to crack*/
const int SAVE_OUT = 0;

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

    if (strcmp(buf2, password) == 0)
    {
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
    double exec_time = 0.0;
    clock_t begin = clock();

    char alphabet[] = "abcdefghijklmnopqrstuwxyz0123456789";

    char passwords[][65] = {"594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06",
                            "ade5880f369fd9765fb6cffdf67b5d4dfb2cf650a49c848a0ce7be1c10e80b23",
                            "83cf8b609de60036a8277bd0e96135751bbc07eb234256d4b65b893360651bf2",
                            "0d335a3bea76dac4e3926d91c52d5bdd716bac2b16db8caf3fb6b7a58cbd92a7"};

    int alphabetLength = strlen(alphabet);

    /* Use a buffer to avoid messing with malloc() in kWordsRecursive */
    char prefix[BUFSIZE];
    memset(prefix, '\0', BUFSIZE);

    size_t const alphalen = strlen(alphabet);

    int found = 0;

    /*find the longest password in the hashes
    so we can save the execution time against it
    The longest password is a more important variable than the amount
    of passwords to crack for the execution time
    */
    size_t longestPasswordLen = 0;

    for (size_t k = 0; k < sizeof(passwords) / sizeof(passwords[0]); k++)
    {
        for (int i = 0; i < alphabetLength + 1; i++)
        {
            if (kWordsRecursive(alphabet, prefix, passwords[k], alphalen, i, i))
            {
                if (SAVE_OUT)
                {
                    if (strlen(prefix) > longestPasswordLen)
                        longestPasswordLen = strlen(prefix);
                }

                found = 1;
                break;
            }
        }
    }

    if (found)
    {
        clock_t end = clock();

        exec_time += (double)(end - begin) / CLOCKS_PER_SEC;

        printf("Execution time: %f seconds\n", exec_time);
        if (SAVE_OUT)
        {
            FILE *f = fopen("timings/BruteForceTiming.txt", "a");
            if (f == NULL)
            {
                printf("Error opening file!\n");
                exit(1);
            }

            fprintf(f, "%d:%f\n", longestPasswordLen, exec_time);
        }
    }
}