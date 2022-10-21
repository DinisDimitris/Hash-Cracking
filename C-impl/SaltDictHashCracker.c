#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sha256/sha256.h"
#include "uthash/include/uthash.h"

#define MAX_LINE_LENGTH 100
#define MAX_KEYS_AMOUNT 6940 /* size of PassworDictionary.txt */
#define MAX_KEY_LENGTH 30    /* let each string have a size of max 30 characters */

/* set to 1 if you wanna save exec time to txt
first column is for the password list length and second for their respective time to crack*/
const int SAVE_OUT = 0;

typedef struct hashdict
{
    char key[65];      /* 65 bytes is hex string + end of string symbol */
    char password[20]; 
    UT_hash_handle hh; /* makes this structure hashable */
} hashdict;

hashdict *item, *dict, *tmp = NULL;

// same with dict hash cracker, but hashes a salted password instead
void StoreHashWithSalt(char *saltedPassword, char *password, hashdict *item)
{
    size_t keylen = strlen(saltedPassword);

    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, saltedPassword, keylen);
    sha256_final(&ctx, buf);

    char *buf2 = malloc(sizeof(buf) * 2 + 1);

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

    char *saltedHashes[][80] = {{"915edb4d39ab6d260e3fb7269f5d9f8cfba3fdc998415298af3e6eb94a82e43e", "27fb57e9"},
                                {"5ddce1dc316e7914ab6af64ef7c00d8b603fac32381db963d9359c3371a84b3a", "b7875b4b"},
                                {"7e3b02bacd934245aa0cb3ea4d2b2f993a8681a650e38a63175374c28c4a7d0d", "ec13ab35"},
                                {"d3136c0cb931acc938de13ed45926eb8764f9ea64af31be479be157480fd3014", "29b49fce"},
                                {"3a9053a077383d11f5963ef0c66b38c7eb8331cdb03bbdcc0e5055307f67331b", "acdabf8a"},
                                {"59c05d8d7b6d29279975141f7329cd77a5dc6942b036f9dfd30cbcb52c320cb4", "64afe39d"},
                                {"c93802a2273a13c2b8378f98dda9f166783cbfce508aeaf570ad0b19a906b4d2", "f0919683"},
                                {"e6a9713791c2ffeddbf6c6c395add47e1fc02ae1fa47febbbdfb694ed688ba61", "081b2451"},
                                {"e6ec51a2ef933920ac1e6d3d8ba6ffac77fe94bfb79518b03cd9b94a14e97d3e", "defb64a3"},
                                {"fbecd00c62b01135f9e588883e80f2710a354c0eb73a33a2c5ab5602cc85f6ad", "017bb5b7"},
                                {"fe8d2120756efb18007d798ad129153ce95c47af01f3f7abc692243ba6b34651", "017bb5b7"},
                                {"ed90f01fb97ccbbd2658bb8cfabacb599a65d4918a730abf379f4f5427d2be34", "081b2451"},
                                {"71b018727d5a8b5d9914552e711efd6c757428742c8753056a945c08b9fa254f", "defb64a3"},
                                {"8c5b87360abaccea310b4d669730217711d4930c59c6c2adbcd5e769a50eadcd", "017bb5b7"},
                                {"f04cb080072c7d4356abba5795fd43f6f0d75d8227f6abdfb322c27c3b7718e7", "017bb5b7"},
                                {"8d11a489044177d7a85057d7ba785e431ac2c2a920e458153d064fef4b180a20", "017bb5b7"},
                                {"ebff5104dba239061e17f850634273ba0100b0ef9acea88cab71492b2a0c0e50", "081b2451"},
                                {"6634a66b7d20c6bc515941e77678b42b129962ec92907906935404bef4c5ed33", "defb64a3"},
                                {"c8d8d943b9c32322099fc9fb872e7abc332558d08226e9c125bd6a0e0f9be967", "017bb5b7"},
                                {"fa8debb7965f3413e956f6dffe08d21b2c37a2111d3ce7615139302ba2f4bdc0", "017bb5b7"}};

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

    for (size_t k = 0; k < sizeof(saltedHashes) / sizeof(saltedHashes[0]); k++)
    {
        for (size_t i = 0; i < (sizeof(keys) / sizeof(keys[0])); i++)
        {
            item = (hashdict *)malloc(sizeof(hashdict));
            if (item == NULL)
            {
                exit(-1);
            }

            char *pwWithSalt = malloc(strlen(keys[i]) + strlen(saltedHashes[k][1]) + 1);

            char *currentPw = keys[i];

            currentPw[strcspn(currentPw, "\n")] = 0;

            strcpy(pwWithSalt, keys[i]);
            strcat(pwWithSalt, saltedHashes[k][1]);

            pwWithSalt[strcspn(pwWithSalt, "\n")] = 0;

            StoreHashWithSalt(pwWithSalt, keys[i], item);

            free(pwWithSalt);
        }
    }

    for (size_t k = 0; k < sizeof(saltedHashes) / sizeof(saltedHashes[0]); k++)
    {
        HASH_FIND_STR(dict, saltedHashes[k][0], item);
        if (item != NULL)
        {
            printf("Password for hash: %s", saltedHashes[k][0]);
            printf(" is: %s\n", item->password);
        }

        else
        {
            printf("Could not find password for hash: %s\n", saltedHashes[k][0]);
        }
    }

    clock_t end = clock();

    exec_time += (double)(end - begin) / CLOCKS_PER_SEC;

    printf("Execution time : %f ms\n", exec_time);

    if (SAVE_OUT)
    {
        FILE *f = fopen("timings/SaltDictCrackerTiming.txt", "a");
        if (f == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }

        fprintf(f, "%d:%f\n", sizeof(saltedHashes) / sizeof(saltedHashes[0]), exec_time);
    }

    HASH_ITER(hh, dict, item, tmp)
    {
        HASH_DEL(dict, item);
        free(item);
    }

    return 0;
}