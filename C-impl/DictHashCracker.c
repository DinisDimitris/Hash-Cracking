#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256/sha256.h"
#include "uthash/include/uthash.h"

#define MAX_LINE_LENGTH 1000

typedef struct hashdict {
    char *key;            /* we'll use this field as the key */
    char *password;
    UT_hash_handle hh; /* makes this structure hashable */
} hashdict;

int main()
{ 
    FILE *textfile;
    char line[MAX_LINE_LENGTH];
    int k =0;

    const char keys[6940][20];
     
    textfile = fopen("hashes/PasswordDictionary.txt", "r");
    if(textfile == NULL)
        return 1;

    while(fgets(line, MAX_LINE_LENGTH, textfile)){
        strncpy(keys[k], line, MAX_LINE_LENGTH);
        k++;
    }
     
    fclose(textfile);
    
    unsigned i;
    hashdict *dict;
    hashdict *head = NULL;

    for(i=0; i < (sizeof(keys)/sizeof(keys[0])); i++) {
        printf("adding key %s\n", keys[i]);
        dict = (hashdict*)malloc(sizeof(hashdict));
        if (dict == NULL) {
            exit(-1);
        }
        dict->key = keys[i];
        HASH_ADD_KEYPTR(hh,head,dict->key,strlen(dict->key),dict);
    }

    for(i=0; i < (sizeof(keys)/sizeof(keys[0])); i++) {
        printf("looking for key %s... ", keys[i]);
        HASH_FIND(hh,head,keys[i],strlen(keys[i]),dict);
        printf("%s.\n", (dict!=NULL)?"found":"not found");
    }

     printf("hash count is %u\n", HASH_COUNT(head));

    return 0;
}