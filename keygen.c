#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]){
    if (argc < 2){
        fprintf(stderr, "UASGE: %s characters\n", argv[0]);
        exit(1);
    }

    int length = atoi(argv[1]);
    char *key_file = malloc(length + 1);
    srand(time(NULL));
    char random_letter;

    for (int i = 0; i < length; i++){
        int value = rand() % 27;
        if (value == 26){
            random_letter = ' ';
        }else{
            random_letter = 'A' + value;
        }
        key_file[i] = random_letter;
    }
    key_file[length] = '\0';
    
    printf("%s\n", key_file);

}