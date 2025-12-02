#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h> 

#include "../include/des_tables.h"
#include "../include/des.h"

#define DIR "my_files"

/*
   VAR DICTIONARY:
   ch    : user choice
   path  : full file path
   k     : secret key
   cnt   : file count
   h     : file handle
*/

// extern functions from file_handler.c
extern void enc_file(char *path, char *key);
extern void dec_file(char *path, char *key);

// helper to select file
int pick_file(char *path_buf) {
    WIN32_FIND_DATA f_data;
    HANDLE h;
    char search[200], list[50][100]; 
    int cnt = 0, ch;
    
    // create folder if not exists
    CreateDirectory(DIR, NULL);

    // loop until user puts a file in folder
    while(1) {
        cnt = 0;
        sprintf(search, "%s\\*", DIR);
        
        h = FindFirstFile(search, &f_data);
        
        if (h != INVALID_HANDLE_VALUE) {
            do {
                // skip . and ..
                if (strcmp(f_data.cFileName, ".") != 0 && strcmp(f_data.cFileName, "..") != 0) {
                    strcpy(list[cnt], f_data.cFileName);
                    cnt++;
                }
            } while (FindNextFile(h, &f_data) != 0 && cnt < 50);
            FindClose(h);
        }

        if (cnt == 0) {
            printf("\nFolder '%s' is empty!\n", DIR);
            printf("Please paste files there and press Enter (or 0 to exit)...\n");
            char c = getchar();
            if (c == '0') return 0;
            while(getchar() != '\n'); // clear buffer
        } else {
            break; // files found
        }
    }

    printf("\n--- FILES ---\n");
    for (int i = 0; i < cnt; i++) 
        printf("[%d] %s\n", i + 1, list[i]);

    printf("Select file (0 to cancel): ");
    scanf("%d", &ch);
    while(getchar() != '\n');

    if (ch > 0 && ch <= cnt) {
        sprintf(path_buf, "%s\\%s", DIR, list[ch - 1]);
        return 1;
    }
    return 0;
}

void ui_enc() {
    char path[256], k[100];
    
    // pick file
    if (!pick_file(path)) return;

    // get key
    printf("Enter 8-char Key: ");
    fgets(k, sizeof(k), stdin);
    k[strcspn(k, "\n")] = 0;

    if (strlen(k) != 8) {
        printf("Key must be 8 chars.\n");
        return;
    }

    enc_file(path, k);
    printf("Press Enter...");
    getchar();
}

void ui_dec() {
    char path[256], k[100];
    
    printf("\n(Make sure .enc file is in the folder)\n");
    if (!pick_file(path)) return;

    printf("Enter 8-char Key: ");
    fgets(k, sizeof(k), stdin);
    k[strcspn(k, "\n")] = 0;

    dec_file(path, k);
    printf("Press Enter...");
    getchar();
}

int main() {
    int ch;
    
    while(1) {
        printf("\n=== DES PROJECT ===\n");
        printf("1. Encrypt\n2. Decrypt\n3. Exit\n>> ");
        
        scanf("%d", &ch);
        while(getchar() != '\n'); 

        if (ch == 1) ui_enc();
        else if (ch == 2) ui_dec();
        else if (ch == 3) break;
        else printf("Invalid.\n");
    }
    return 0;
}