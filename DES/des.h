#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTION 1
#define DECRYPTION 0

#define DES_KEY_SIZE 8 // DES key is 8 bytes long
#define BLOCK_SIZE 8

typedef struct {
	uint8_t k[8];
	uint8_t c[4];
	uint8_t d[4];
} key_set;


#define DES_KEY_SIZE 8 // DES key is 8 bytes long
#define BLOCK_SIZE 8

void generate_sub_keys(uint8_t* main_key, key_set* key_sets);
void IP(uint8_t* in, uint8_t* state);
void F(uint8_t mode, uint8_t* state, uint8_t* l, uint8_t* r, key_set* key_sets);
void des(uint8_t mode, uint8_t* in, uint8_t* processed_piece, uint8_t* key);
void twodes(uint8_t mode, uint8_t* p, uint8_t* c, uint8_t* key1, uint8_t* key2);
void print_string_c(uint8_t* input, int len);
void print_string_hex(uint8_t* input, int len);
#endif
