#ifndef DES_H
#define DES_H

// function declarations
void key_gen(char *key);
void des_enc(unsigned char *blk);
void des_dec(unsigned char *blk);

#endif