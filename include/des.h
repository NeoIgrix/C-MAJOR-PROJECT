#ifndef DES_H
#define DES_H

// These are the functions we created in des_logic.c
// We declare them here so other files can use them.

void generate_subkeys(char *input_key);
void des_encrypt_block(unsigned char *block);
void des_decrypt_block(unsigned char *block);

#endif