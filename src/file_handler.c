#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/des.h"

long get_file_size(FILE *f) {
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    return size;
}

void encrypt_file(char *input_path, char *key) {
    FILE *in = fopen(input_path, "rb"); 
    if (!in) {
        printf("[!] Error: Could not open file %s\n", input_path);
        return;
    }

    char output_path[200];
    sprintf(output_path, "%s.enc", input_path);
    FILE *out = fopen(output_path, "wb"); 

    generate_subkeys(key);

    unsigned char buffer[8];
    int bytes_read;

    printf("[*] Encrypting chunks...\n");

    while ((bytes_read = fread(buffer, 1, 8, in)) > 0) {
        if (bytes_read < 8) {
            int padding_val = 8 - bytes_read;
            for (int i = bytes_read; i < 8; i++) {
                buffer[i] = padding_val;
            }
            des_encrypt_block(buffer);
            fwrite(buffer, 1, 8, out);
        } else {
            des_encrypt_block(buffer);
            fwrite(buffer, 1, 8, out);
        }
    }

    long size = get_file_size(in); 
    if (size % 8 == 0) {
        for (int i = 0; i < 8; i++) buffer[i] = 8;
        des_encrypt_block(buffer);
        fwrite(buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
    
    // Delete original file
    printf("[Security] Deleting original file: %s\n", input_path);
    if (remove(input_path) == 0) {
        printf("[Security] Original file deleted successfully.\n");
    } else {
        printf("[!] Warning: Could not delete original file. Check permissions.\n");
    }
    
    printf("[Success] File Encrypted -> %s\n", output_path);
}

void decrypt_file(char *input_path, char *key) {
    FILE *in = fopen(input_path, "rb");
    if (!in) {
        printf("[!] Error: Could not open file %s\n", input_path);
        return;
    }

    // 1. Create a temporary string for the original filename (without .enc)
    char temp_path[200];
    strncpy(temp_path, input_path, strlen(input_path) - 4);
    temp_path[strlen(input_path) - 4] = '\0'; 
    
    // 2. Intelligent Path Splitting
    // We want to turn "my_files\secret.txt" into "my_files\decrypted_secret.txt"
    char final_path[300];
    
    // Find the last slash (works for Windows '\' or Linux '/')
    char *last_slash = strrchr(temp_path, '\\');
    if (!last_slash) last_slash = strrchr(temp_path, '/');
    
    if (last_slash) {
        // We found a slash. Copy the folder path first.
        int folder_len = last_slash - temp_path + 1; // Include the slash
        strncpy(final_path, temp_path, folder_len);
        final_path[folder_len] = '\0'; // Terminate string
        
        // Now append "decrypted_" and then the filename
        strcat(final_path, "decrypted_");
        strcat(final_path, last_slash + 1); // +1 skips the slash itself
    } else {
        // No slash found (file is in current folder)
        sprintf(final_path, "decrypted_%s", temp_path);
    }

    FILE *out = fopen(final_path, "wb");
    if (!out) {
        printf("[!] Error: Could not create output file %s\n", final_path);
        fclose(in);
        return;
    }

    generate_subkeys(key);

    unsigned char buffer[8];
    unsigned char prev_buffer[8]; 
    int first_block = 1;
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, 8, in)) == 8) {
        des_decrypt_block(buffer);
        
        if (!first_block) {
            fwrite(prev_buffer, 1, 8, out);
        }
        memcpy(prev_buffer, buffer, 8);
        first_block = 0;
    }

    int padding_val = prev_buffer[7];
    
    if (padding_val > 0 && padding_val <= 8) {
        fwrite(prev_buffer, 1, 8 - padding_val, out);
    } else {
        printf("[Warning] Invalid padding detected. Wrong Key?\n");
        fwrite(prev_buffer, 1, 8, out);
    }

    fclose(in);
    fclose(out);
    
    printf("[Success] File Decrypted -> %s\n", final_path);
}