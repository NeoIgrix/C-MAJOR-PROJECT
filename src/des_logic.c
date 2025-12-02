#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/des_tables.h"

/*
   VARIABLE DICTIONARY:
   sk[16][6] : stores the 16 generated subkeys
   c, d      : variables for left/right halves during key gen
   val       : temporary integer value
   pos       : position index
   l, r      : left and right halves of the data block
   res       : result variable
*/

// global array to store 16 keys (48 bits each)
unsigned char sk[16][6]; 

// sets a bit at pos to val (0 or 1)
void set_bit(unsigned char *arr, int pos, int val) {
    int byte = (pos - 1) / 8;
    int bit = 7 - ((pos - 1) % 8);
    
    if (val == 1) arr[byte] |= (1 << bit);
    else          arr[byte] &= ~(1 << bit);
}

// gets bit from pos
int get_bit(unsigned char *arr, int pos) {
    int byte = (pos - 1) / 8;
    int bit = 7 - ((pos - 1) % 8);
    return (arr[byte] >> bit) & 1;
}

// generates the 16 rounds of keys
void key_gen(char *key) {
    unsigned char k_block[8];
    memcpy(k_block, key, 8);

    // using unsigned long long for 64-bit storage
    unsigned long long c = 0, d = 0;

    // PC1 permutation
    for (int i = 0; i < 28; i++) {
        if (get_bit(k_block, PC1[i])) c |= (1ULL << (27 - i));
        if (get_bit(k_block, PC1[i + 28])) d |= (1ULL << (27 - i));
    }

    // loop for 16 keys
    for (int i = 0; i < 16; i++) {
        int s = SHIFTS[i]; // get shift amount
        
        // circular shift logic
        c = ((c << s) | (c >> (28 - s))) & 0x0FFFFFFF;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFFFFFF;

        unsigned long long comb = (c << 28) | d;
        
        // clear old key
        memset(sk[i], 0, 6); 

        // PC2 permutation
        for (int j = 0; j < 48; j++) {
            int val = (comb >> (56 - PC2[j])) & 1;
            set_bit(sk[i], j + 1, val);
        }
    }
}

// the main function inside the rounds
unsigned long long f_func(unsigned long long r, unsigned char *sub_k) {
    // expansion
    unsigned long long exp_r = 0;
    for(int i=0; i<48; i++) {
        if( (r >> (32 - E[i])) & 1 ) 
             exp_r |= (1ULL << (47-i));
    }
    
    // xor with subkey
    unsigned long long k_int = 0;
    for(int i=0; i<48; i++) {
         if(get_bit(sub_k, i+1)) k_int |= (1ULL << (47-i));
    }
    unsigned long long xor_res = exp_r ^ k_int;
    
    // s-box substitution
    unsigned long long s_out = 0;
    for(int i=0; i<8; i++) {
        int chk = (xor_res >> ((7-i)*6)) & 0x3F; // take 6 bits
        
        int row = ((chk & 0x20) >> 4) | (chk & 0x01);
        int col = (chk >> 1) & 0x0F;
        
        int val = S_BOX[i][row][col];
        s_out |= ((unsigned long long)val << ((7-i)*4));
    }
    
    // p permutation
    unsigned long long res = 0;
    for(int i=0; i<32; i++) {
        if( (s_out >> (32 - P[i])) & 1 ) {
            res |= (1ULL << (31-i));
        }
    }
    return res;
}

// processing one block of 64 bits
void proc(unsigned char *blk, int mode) {
    // mode 0: encrypt, mode 1: decrypt
    
    unsigned long long data = 0;
    for(int i=0; i<8; i++) data = (data << 8) | blk[i];
    
    // initial permutation
    unsigned long long p_inp = 0;
    for(int i=0; i<64; i++) {
        if ( (data >> (64 - IP[i])) & 1 ) {
            p_inp |= (1ULL << (63-i));
        }
    }
    
    unsigned long long l = (p_inp >> 32) & 0xFFFFFFFF;
    unsigned long long r = p_inp & 0xFFFFFFFF;
    
    // 16 rounds loop
    for(int i=0; i<16; i++) {
        unsigned long long old_r = r;
        
        // decrypt uses keys in reverse
        int k_idx = (mode == 0) ? i : (15 - i);
        
        r = l ^ f_func(r, sk[k_idx]);
        l = old_r;
    }
    
    // final swap
    unsigned long long pre = (r << 32) | l;
    
    // inverse permutation
    unsigned long long fin = 0;
    for(int i=0; i<64; i++) {
        if ( (pre >> (64 - IP_INV[i])) & 1 ) {
            fin |= (1ULL << (63-i));
        }
    }
    
    // putting back to char array
    for(int i=0; i<8; i++) {
        blk[i] = (fin >> ((7-i)*8)) & 0xFF;
    }
}

// wrapper functions
void des_enc(unsigned char *blk) { proc(blk, 0); }
void des_dec(unsigned char *blk) { proc(blk, 1); }