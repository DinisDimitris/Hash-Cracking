#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256/sha256.h"
#include "uthash/include/uthash.h"

#define MAX_LINE_LENGTH 100
#define MAX_KEYS_AMOUNT 6940 /* size of PassworDictionary.txt */
#define MAX_KEY_LENGTH 30 /* let each string have a size of max 20 characters */

typedef struct hashdict {
    char key[65];            /* we'll use this field as the key */
    char password[20];  /* 65 bytes is hex string + end of string symbol */
    UT_hash_handle hh; /* makes this structure hashable */
} hashdict;

hashdict *item, *dict, *tmp = NULL;

void StoreHash(char *password, hashdict *item )
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
    for (k = 0; k < sizeof(buf) ; k++)
    {
        ptr += sprintf(ptr, "%02x", buf[k]); /*turn byte[] into char* (hex representation) */
    }

    strcpy(item->password, password);

    strcpy(item->key,  buf2);

    HASH_ADD_STR(dict, key, item);

    free(buf2);
}

int main()
{ 
    FILE *textfile;
    char line[MAX_LINE_LENGTH];
    int k =0;

    const char keys[MAX_KEYS_AMOUNT][MAX_KEY_LENGTH];
     
    textfile = fopen("hashes/PasswordDictionary.txt", "r");
    if (textfile == NULL ) {
        perror("can't open: ");
        exit(-1);
    }

    while(fgets(line, MAX_LINE_LENGTH, textfile)){
        strncpy(keys[k], line, MAX_LINE_LENGTH);
        k++;
    }
     
    fclose(textfile);

    for(size_t i =0; i < (sizeof(keys)/sizeof(keys[0])); i++) {
        //printf("adding key %s\n", keys[i]);
        item = (hashdict*)malloc(sizeof(hashdict));
        if (item == NULL) {
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
                                "cbb05a10a2fc5cc96ce5da00a12acc54f594eadb85363de665f3e5dcb81d0e51"};

    for (size_t k = 0; k < sizeof(hashesToCrack) / sizeof(hashesToCrack[0]); k++)
    {
        HASH_FIND_STR(dict,hashesToCrack[k],item);
        if (item !=NULL)
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

    HASH_ITER(hh, dict, item, tmp) {
      HASH_DEL(dict, item);
      free(item);
    }

    return 0;
}