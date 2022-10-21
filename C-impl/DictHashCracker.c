#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sha256/sha256.h"
#include "uthash/include/uthash.h"

#define MAX_LINE_LENGTH 100
#define MAX_KEYS_AMOUNT 6940 /* size of PassworDictionary.txt */
#define MAX_KEY_LENGTH 20    /* let each string have a size of max 20 characters */

/* set to 1 if you wanna save exec time to txt
first column is for the password list length and second for their respective time to crack*/
const int SAVE_OUT = 0;

typedef struct hashdict
{
    char key[65];      /* we'll use this field as the key,  65 bytes is hex string + end of string symbol */ 
    char password[20]; 
    UT_hash_handle hh; /* makes this structure hashable */
} hashdict;

hashdict *item, *dict, *tmp = NULL;

void StoreHash(char *password, hashdict *item)
{
    password[strcspn(password, "\n")] = 0;
    int keylen = strlen(password);

    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, password, keylen);
    sha256_final(&ctx, buf);

    char *buf2 = malloc(sizeof(buf) * 2);

    char *ptr = buf2;

    int k;
    for (k = 0; k < sizeof(buf); k++)
    {
        ptr += sprintf(ptr, "%02x", buf[k]); /*turn byte[] into char* (hex representation) */
    }

    strcpy(item->password, password);

    strcpy(item->key, buf2);

    HASH_ADD_STR(dict, key, item);

    free(buf2);
}

int main()
{
    double exec_time = 0.0;
    clock_t begin = clock();

    FILE *textfile;
    char line[MAX_LINE_LENGTH];
    int k = 0;

    const char keys[MAX_KEYS_AMOUNT][MAX_KEY_LENGTH];

    textfile = fopen("hashes/PasswordDictionary.txt", "r");
    if (textfile == NULL)
    {
        perror("can't open: ");
        exit(-1);
    }

    while (fgets(line, MAX_LINE_LENGTH, textfile))
    {
        strncpy(keys[k], line, MAX_LINE_LENGTH);
        k++;
    }

    fclose(textfile);

    for (size_t i = 0; i < (sizeof(keys) / sizeof(keys[0])); i++)
    {
        // printf("adding key %s\n", keys[i]); takes O(n)
        // create new dict link for each password
        item = (hashdict *)malloc(sizeof(hashdict));
        if (item == NULL)
        {
            exit(-1);
        }

        StoreHash(keys[i], item);
    }

    char hashesToCrack[][65] = {"1a7648bc484b3d9ed9e2226d223a6193d64e5e1fcacd97868adec665fe12b924",
                                "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
                                "48054a90032bf1348452fd74f3500ef8d2318d9b5582b07449b3b59db841eecd",
                                "09537eae89936399905661760584b19f6ff3af4bb807cee0bb663f64b07eea8e",
                                "e7798dc61be73b717402d76cbfaaef41c36c85c027a59abd74abbc8c8288bd4f",
                                "0f42bcbeedf89160a6cf7ccafe68080f2aafb73b3ef057df6b5e22f1294d0a10",
                                "13989fe9c124d4dfca4e2661dcf8449f49a76fb69f9725612a130622ff3f9bfb",
                                "d780c9776eb7d602c805af9ed7aa78225b36af0decb6be51045dcbfa661594a3",
                                "d2d03c10a4f2c361dbeff74dab0019264e37336f9ef04831943d0f07c0ad52c7",
                                "cbb05a10a2fc5cc96ce5da00a12acc54f594eadb85363de665f3e5dcb81d0e51",
                                "ed068fe14bdd683f4f8387d2d47881f360261d22ded821294a882d46e72116c2",
                                "385ee48e6f296b43ad349668136398a3f8cb70f456cfbb96278a18312a88b961",
                                "6b67ce1731ce99db3c0dfdde156cd1df6cd877dace071ddab14568a1acc9cd7d",
                                "351b70b9910cb1225c5dc350bb2f88f8c9f05b4b511654c9158c54d12c700333",
                                "7b524ab69c6f8514fdd9756e822e1749ef1ea5b0eb52398d2b3c74e701182025",
                                "d497c74b778d495d53c8aa07623df047246aca540d6d3313bcc8ae8188e0a192",
                                "9c1bb78d6aaf2f35a75444b5cda56636fba49896bb071f02a993fa495afb9350",
                                "3e3a519e9bffb5ffea8fd3508739c5ee6187d0910278e3211b4e20da4aff0b43",
                                "a432d55171960b9689b344bdf80b825a29951ba67a32f165b7341033a3112171",
                                "ea23726dd0fd4e4dd85eb695843fcdd3b6928ab5561fa959f1523bd36bb613fe"};

    for (size_t k = 0; k < sizeof(hashesToCrack) / sizeof(hashesToCrack[0]); k++)
    {
        HASH_FIND_STR(dict, hashesToCrack[k], item);
        if (item != NULL)
        {
            printf("Password for hash: %s", hashesToCrack[k]);
            printf(" is: %s\n", item->password);
        }

        else
        {
            printf("Could not find password for hash: %s\n", hashesToCrack[k]);
        }
    }

    // printf(" hash count is %u\n", HASH_COUNT(dict)); get hash count

    HASH_ITER(hh, dict, item, tmp)
    {
        HASH_DEL(dict, item);
        free(item);
    }

    clock_t end = clock();

    exec_time += (double)(end - begin) / CLOCKS_PER_SEC;

    printf("Execution time: %f ms\n", exec_time);
    if (SAVE_OUT)
    {
        FILE *f = fopen("timings/DictCrackerTiming.txt", "a");
        if (f == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }

            fprintf(f, "%d:%f\n", sizeof(hashesToCrack) / sizeof(hashesToCrack[0]), exec_time);
    }

    return 0;
}