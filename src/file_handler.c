#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/des.h"

/*
   VAR DICTIONARY:
   f       : file ptr
   sz      : file size
   in, out : input/output streams
   buf     : data buffer
   pad     : padding value
   ptr     : pointer to find slash in path
*/

long get_sz(FILE *f) {
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    return sz;
}

void enc_file(char *path, char *key) {
    FILE *in = fopen(path, "rb"); 
    if (!in) { printf("Error opening file.\n"); return; }

    char out_path[200];
    sprintf(out_path, "%s.enc", path);
    FILE *out = fopen(out_path, "wb"); 

    key_gen(key); 

    unsigned char buf[8];
    int read;

    printf("Encrypting...\n");

    while ((read = fread(buf, 1, 8, in)) > 0) {
        if (read < 8) {
            // adding padding
            int pad = 8 - read;
            for (int i = read; i < 8; i++) buf[i] = pad;
            des_enc(buf);
            fwrite(buf, 1, 8, out);
        } else {
            des_enc(buf);
            fwrite(buf, 1, 8, out);
        }
    }

    // if size is perfect multiple of 8, add full block padding
    long sz = get_sz(in); 
    if (sz % 8 == 0) {
        for (int i = 0; i < 8; i++) buf[i] = 8;
        des_enc(buf);
        fwrite(buf, 1, 8, out);
    }

    fclose(in);
    fclose(out);
    
    // DELETE ORIGINAL FILE
    printf("Deleting original file...\n");
    if (remove(path) == 0) {
        printf("Original deleted.\n");
    } else {
        printf("Could not delete original.\n");
    }
    
    printf("Encrypted file: %s\n", out_path);
}

void dec_file(char *path, char *key) {
    FILE *in = fopen(path, "rb");
    if (!in) { printf("Error opening file.\n"); return; }

    // 1. remove .enc extension
    char tmp[200];
    strncpy(tmp, path, strlen(path) - 4);
    tmp[strlen(path) - 4] = '\0'; // e.g., "my_files\image.jpg"

    // 2. fix path string
    char final[300];
    
    // find the last slash (works for \ or /)
    char *ptr = strrchr(tmp, '\\');
    if (!ptr) ptr = strrchr(tmp, '/');

    if (ptr) {
        // found a folder separator
        int len = ptr - tmp + 1; // length up to slash
        
        strncpy(final, tmp, len); // copy "my_files\"
        final[len] = '\0';
        
        strcat(final, "dec_");    // add prefix
        strcat(final, ptr + 1);   // add filename
    } else {
        // no folder found, just rename
        sprintf(final, "dec_%s", tmp);
    }

    FILE *out = fopen(final, "wb");
    if (!out) { printf("Error creating output file.\n"); fclose(in); return; }
    
    key_gen(key);

    unsigned char buf[8], prev[8]; 
    int first = 1;
    int read;

    while ((read = fread(buf, 1, 8, in)) == 8) {
        des_dec(buf);
        
        if (!first) fwrite(prev, 1, 8, out);
        memcpy(prev, buf, 8);
        first = 0;
    }

    // remove padding
    int pad = prev[7];
    if (pad > 0 && pad <= 8) fwrite(prev, 1, 8 - pad, out);
    else fwrite(prev, 1, 8, out);

    fclose(in);
    fclose(out);
    
    printf("Decrypted to: %s\n", final);
}