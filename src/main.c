#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <windows.h> // Required for folder handling

// Use relative paths because we are in /src, headers are in /include
#include "../include/des_tables.h"
#include "../include/des.h"

#define DATA_FOLDER "my_files"

// --- PROTOTYPES ---
void print_header();
void get_valid_key(char *key_buffer);
void encrypt_file_interface();
void decrypt_file_interface();
int select_file_from_folder(char *selected_path_buffer);
int confirm_safety_protocol(); // New Safety Check Function

// Helper functions (defined in file_handler.c)
extern void encrypt_file(char *input_path, char *key);
extern void decrypt_file(char *input_path, char *key);

int main() {
    int choice;
    srand(time(0)); 

    while(1) {
        print_header();
        printf("\nSelect an option:\n");
        printf("[1] Encrypt a File\n");
        printf("[2] Decrypt a File\n");
        printf("[3] Exit\n");
        printf(">> ");
        
        scanf("%d", &choice);
        while(getchar() != '\n'); 

        switch(choice) {
            case 1:
                encrypt_file_interface();
                break;
            case 2:
                decrypt_file_interface();
                break;
            case 3:
                printf("\nExiting Secure System. Stay Safe!\n");
                return 0;
            default:
                printf("\n[!] Invalid Option.\n");
        }
    }
    return 0;
}

// --- NEW SAFETY LOGIC ---
int confirm_safety_protocol() {
    char response;
    
    printf("\n[SAFETY CHECK] Secure Delete Protocol is ACTIVE.\n");
    printf("The original file will be PERMANENTLY deleted after encryption.\n");
    
    // Level 1: Backup Check
    printf(">> Have you backed up this file elsewhere? (y/n): ");
    scanf("%c", &response);
    while(getchar() != '\n'); // Clear buffer
    
    if (tolower(response) == 'y') {
        return 1; // User is safe, proceed
    }
    
    // Level 2: Final Warning (Only if they said No to backup)
    printf("\n[!!! WARNING !!!]\n");
    printf("You indicated you do NOT have a backup.\n");
    printf("If you proceed, the original file is gone forever.\n");
    printf(">> Do you still want to continue? (y/n): ");
    
    scanf("%c", &response);
    while(getchar() != '\n');
    
    if (tolower(response) == 'y') {
        printf("[*] User acknowledged risk. Proceeding...\n");
        return 1;
    }
    
    printf("[-] Operation Cancelled by user.\n");
    return 0;
}

// --- INTELLIGENT FILE SELECTOR ---
int select_file_from_folder(char *selected_path_buffer) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char search_path[200];
    char file_list[50][100]; 
    int file_count = 0;
    int choice;
    
    // 1. Check/Create Folder
    if (CreateDirectory(DATA_FOLDER, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        // Folder is good
    } else {
        printf("[!] Error: Could not create '%s' folder.\n", DATA_FOLDER);
        return 0;
    }

    sprintf(search_path, "%s\\*", DATA_FOLDER);

    // 2. The "Refresh" Loop
    while (1) {
        file_count = 0;
        hFind = FindFirstFile(search_path, &findData);
        
        // Count valid files
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    strcpy(file_list[file_count], findData.cFileName);
                    file_count++;
                }
            } while (FindNextFile(hFind, &findData) != 0 && file_count < 50);
            FindClose(hFind);
        }

        if (file_count == 0) {
            printf("\n[Action Required] The '%s' folder is empty.\n", DATA_FOLDER);
            printf("Please paste your files into the '%s' folder now.\n", DATA_FOLDER);
            printf(">> Press [ENTER] once you have pasted the files (or '0' to cancel): ");
            
            char check = getchar();
            if (check == '0') return 0; // Allow exit
            // Loop restarts and checks again
        } else {
            break; // Files found!
        }
    }

    // 3. Display Files
    printf("\n--- FILES FOUND IN '%s' ---\n", DATA_FOLDER);
    for (int i = 0; i < file_count; i++) {
        printf("[%d] %s\n", i + 1, file_list[i]);
    }

    printf("\nSelect file number (0 to cancel): ");
    scanf("%d", &choice);
    while(getchar() != '\n');

    if (choice > 0 && choice <= file_count) {
        sprintf(selected_path_buffer, "%s\\%s", DATA_FOLDER, file_list[choice - 1]);
        return 1;
    }
    
    printf("[*] Selection Cancelled.\n");
    return 0;
}

void print_header() {
    printf("\n======================================\n");
    printf("      CRIMSON DES ENCRYPTION V4.0     \n");
    printf("======================================\n");
}

void get_valid_key(char *key_buffer) {
    char input[100];
    int valid = 0;
    while (!valid) {
        printf("\nEnter a Secret Key (8 characters): ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 8) {
            strcpy(key_buffer, input);
            valid = 1;
        } else {
            printf("[!] Key must be exactly 8 characters.\n");
        }
    }
}

void encrypt_file_interface() {
    char full_path[256];
    char key[9]; 
    
    // 1. Select File (and prompt user to paste if empty)
    if (!select_file_from_folder(full_path)) return;

    // 2. Safety Check (The Backup Warning)
    if (!confirm_safety_protocol()) return;

    // 3. Get Key and Execute
    get_valid_key(key);
    printf("\n[Process] Encrypting: %s\n", full_path);
    encrypt_file(full_path, key);
    
    printf("\nDone! Press Enter to return to menu...");
    getchar();
}

void decrypt_file_interface() {
    char full_path[256];
    char key[9];
    
    printf("\n[Tip] Please paste your .enc file into the folder if not present.\n");
    
    if (!select_file_from_folder(full_path)) return;

    // No safety check needed for Decryption (we aren't deleting the source dangerously)
    get_valid_key(key);
    
    printf("\n[Process] Decrypting: %s\n", full_path);
    decrypt_file(full_path, key);
    
    printf("\nDone! Press Enter to return to menu...");
    getchar();
}