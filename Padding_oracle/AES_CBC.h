#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>

//print array in hex format
void print_hex(uint8_t *buf, uint32_t c);
//print array in character format
void print_c(uint8_t *buf, uint32_t c);

//convert ASCII code hex to decimal equivalent
uint8_t hexdigit_value(uint8_t c);

//parse function to transform hex string to decimal array
void parse(uint32_t length, uint8_t *in, uint8_t *out);

//cipher plaintext of length plen with AES-CBC. Result of length clen is stored in ciphertext
void cipher_AES_CBC(uint8_t* plaintext, uint32_t plen, uint8_t* ciphertext, uint32_t clen);

//decipher ciphertext of length clen with AES-CBC. Result of length plen is stored in plaintext when pad is correct, else plen=0
uint32_t decipher_AES_CBC_PO(uint8_t* plaintext, uint8_t* ciphertext, uint32_t clen);

//check pad of deciphered ciphertext stored in buf
uint8_t check_pad (uint8_t pad, uint8_t* buf);


