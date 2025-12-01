#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/des_tables.h"

// --- UTILITY: BIT MANIPULATION ---

// This function sets a specific bit in a 64-bit key
// "pos" is the position (1-64), "value" is 0 or 1
void set_bit(unsigned char *data, int pos, int value) {
    int byte_index = (pos - 1) / 8;
    int bit_index = 7 - ((pos - 1) % 8); // DES uses Big Endian (bit 1 is far left)
    
    if (value == 1)
        data[byte_index] |= (1 << bit_index);
    else
        data[byte_index] &= ~(1 << bit_index);
}

// This checks if a bit is 1 or 0 at a position
int get_bit(unsigned char *data, int pos) {
    int byte_index = (pos - 1) / 8;
    int bit_index = 7 - ((pos - 1) % 8);
    
    return (data[byte_index] >> bit_index) & 1;
}

// --- STEP 1: KEY GENERATION ---

// We need storage for 16 subkeys (each is 48 bits, so 6 bytes)
unsigned char subkeys[16][6]; 

void generate_subkeys(char *input_key) {
    // 1. Convert the 8-char string (e.g., "Ti190306") into raw bits
    // We treat the char array as our 64-bit block.
    unsigned char key_block[8];
    memcpy(key_block, input_key, 8);

    // Variables to hold our 56-bit key (28 bits Left, 28 bits Right)
    // We use "long long" (64 bit int) to store them easily
    unsigned long long C = 0, D = 0;

    // 2. Perform PC-1 Permutation
    // This scrambles the original key and drops 8 bits (parity bits)
    // We split the result into C (Left) and D (Right)
    for (int i = 0; i < 28; i++) {
        int bit = get_bit(key_block, PC1[i]);
        if (bit) C |= (1ULL << (27 - i)); // Fill C
    }
    for (int i = 0; i < 28; i++) {
        int bit = get_bit(key_block, PC1[i + 28]);
        if (bit) D |= (1ULL << (27 - i)); // Fill D
    }

    // 3. The Loop for 16 Rounds
    printf("\n--- GENERATING SUBKEYS ---\n");
    for (int round = 0; round < 16; round++) {
        // A. Shift Left (Circular Shift)
        // We look up how many shifts to do in our SHIFTS table
        int shifts = SHIFTS[round];
        
        // We use a trick to do circular shifting on 28-bit numbers
        // ((C << shifts) | (C >> (28 - shifts))) & 0xFFFFFFF
        // The "& 0xFFFFFFF" keeps it to 28 bits
        C = ((C << shifts) | (C >> (28 - shifts))) & 0x0FFFFFFF;
        D = ((D << shifts) | (D >> (28 - shifts))) & 0x0FFFFFFF;

        // B. PC-2 Permutation (Compression)
        // Combine C and D, then pick 48 bits to form the Subkey
        unsigned long long combined_key = (C << 28) | D;
        
        // Clear the space for the new subkey
        memset(subkeys[round], 0, 6); 

        for (int i = 0; i < 48; i++) {
            // PC2 table values are 1-56. We need to find that bit in combined_key.
            // Note: This bit extraction logic is slightly different because 
            // combined_key is a single integer, not a byte array.
            int pos = PC2[i];
            int bit_val = (combined_key >> (56 - pos)) & 1;
            
            // Store this bit in our subkey array
            set_bit(subkeys[round], i + 1, bit_val);
        }
        
        // Debug: Print the first byte of each subkey to prove it works
        printf("Round %02d Key Generated: 0x%02X...\n", round + 1, subkeys[round][0]);
    }
    printf("--- KEY GENERATION COMPLETE ---\n");
}

// --- STEP 2: THE FEISTEL FUNCTION (The "Mixer") ---
// This takes the Right half (32 bits) and a Subkey (48 bits)
// and produces a 32-bit scrambled result.
unsigned long long feistel_function(unsigned long long R, unsigned char *subkey) {
    // 1. Expansion (32 bits -> 48 bits)
    unsigned long long expanded_R = 0;
    for(int i=0; i<48; i++) {
        if( (R >> (32 - E[i])) & 1 ) { // E is 1-based index, bit 1 is MSB (32-1=31 shift)
             expanded_R |= (1ULL << (47-i));
        }
    }
    
    // 2. XOR with Subkey
    unsigned long long subkey_int = 0;
    for(int i=0; i<48; i++) {
        int bit = get_bit(subkey, i+1);
         if(bit) subkey_int |= (1ULL << (47-i));
    }
    unsigned long long xored = expanded_R ^ subkey_int;
    
    // 3. S-Boxes (48 bits -> 32 bits)
    unsigned long long sbox_output = 0;
    for(int i=0; i<8; i++) {
        // Extract 6 bits for this S-Box
        int chunk = (xored >> ((7-i)*6)) & 0x3F; 
        
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01); // Bits 1 and 6
        int col = (chunk >> 1) & 0x0F;                    // Bits 2,3,4,5
        
        int val = S_BOX[i][row][col];
        
        // Append this 4-bit value to the output
        sbox_output |= ((unsigned long long)val << ((7-i)*4));
    }
    
    // 4. Permutation P (32 bits -> 32 bits)
    unsigned long long result = 0;
    for(int i=0; i<32; i++) {
        if( (sbox_output >> (32 - P[i])) & 1 ) {
            result |= (1ULL << (31-i));
        }
    }
    return result;
}

// --- STEP 3: ENCRYPT/DECRYPT A SINGLE 64-BIT BLOCK ---
// This handles the IP, the 16 rounds, and IP-Inverse
void process_block(unsigned char *block, int mode) {
    // Mode 0 = Encrypt, 1 = Decrypt
    
    // 1. Initial Permutation (IP)
    unsigned long long data_val = 0;
    for(int i=0; i<8; i++) { // Convert byte array to long long
        data_val = (data_val << 8) | block[i];
    }
    
    unsigned long long permuted_input = 0;
    for(int i=0; i<64; i++) {
        if ( (data_val >> (64 - IP[i])) & 1 ) {
            permuted_input |= (1ULL << (63-i));
        }
    }
    
    // Split into Left and Right
    unsigned long long L = (permuted_input >> 32) & 0xFFFFFFFF;
    unsigned long long R = permuted_input & 0xFFFFFFFF;
    
    // 2. The 16 Rounds
    for(int i=0; i<16; i++) {
        unsigned long long old_R = R;
        
        // For decryption, we use subkeys in REVERSE order (15 down to 0)
        int key_index = (mode == 0) ? i : (15 - i);
        
        R = L ^ feistel_function(R, subkeys[key_index]);
        L = old_R;
    }
    
    // 3. The "Pre-Output" Swap (Standard DES behavior: R becomes Left, L becomes Right)
    unsigned long long pre_output = (R << 32) | L;
    
    // 4. Final Permutation (IP Inverse)
    unsigned long long final_output = 0;
    for(int i=0; i<64; i++) {
        if ( (pre_output >> (64 - IP_INV[i])) & 1 ) {
            final_output |= (1ULL << (63-i));
        }
    }
    
    // Put back into char array
    for(int i=0; i<8; i++) {
        block[i] = (final_output >> ((7-i)*8)) & 0xFF;
    }
}

// Wrapper functions
void des_encrypt_block(unsigned char *block) {
    process_block(block, 0);
}

void des_decrypt_block(unsigned char *block) {
    process_block(block, 1);
}