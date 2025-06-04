#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "des.h"
 
void print_plaintext(uint8_t *t);
void print_key(uint8_t *key, int i);

int main (void)
{
	//Bruteforce attack 2DES
	//some of the most significant bytes of key1 and key2 are unkown	
	int bytes_k2=1; 
	int bytes_k1=2;
	uint8_t key1[DES_KEY_SIZE]={0x00,0x00,0x83,0x48,0x42,0x20,0x3f,0x0f}; 
	uint8_t key2[DES_KEY_SIZE]={0x00,0xe5,0x33,0x48,0x36,0x54,0x3f,0x30}; 
	uint64_t iterations_k2 = pow(2, 8*bytes_k2);
	uint64_t iterations_k1 = pow(2, 8*bytes_k1);

	
	//3 plaintext and ciphertext pairs are known (p1,c1), (p2,c2), (p3,c3)
	uint8_t p1[BLOCK_SIZE]="Can you ";
	uint8_t c1[BLOCK_SIZE]={0x5a, 0x72, 0xd1, 0x75, 0x69, 0xfa, 0xe4, 0xba};
	uint8_t p2[BLOCK_SIZE]="find the";
	uint8_t c2[BLOCK_SIZE]={0x1d, 0x9b, 0x47, 0x2a, 0x82, 0xbc, 0xf0, 0x5c};
	uint8_t p3[BLOCK_SIZE]="keys????";
	uint8_t c3[BLOCK_SIZE]={0xbc, 0xe7, 0xe1, 0x41, 0x61, 0x9c, 0xc1, 0xa0};
	//Can you determine p4 from c4?
	uint8_t c4[BLOCK_SIZE]={0x46, 0x00, 0x16, 0xda, 0x57, 0xb2, 0x6a, 0xfd};
	uint8_t p4[BLOCK_SIZE];
	uint8_t cipher[BLOCK_SIZE];
	uint8_t p5[BLOCK_SIZE];
	uint8_t p6[BLOCK_SIZE];
	uint8_t p7[BLOCK_SIZE];
	uint8_t p8[BLOCK_SIZE];
	int aurkitua = 0;

	clock_t start, finish;
	double time_taken;
	start = clock();
	
	for (int i = 0; i < iterations_k2; i++) {
		key1[0]=0x00;
		key1[1]=0x00;

		for (int j = 0; j < iterations_k1; j++) {
			twodes(ENCRYPTION, p1, cipher, key1, key2);
			if(memcmp(cipher, c1, sizeof(cipher)) == 0) {
				aurkitua = 1;
				break;
			}
			
			if(key1[1]==0xff) {
				key1[1]=0x00;
				key1[0]++;
			} else {
				key1[1]++;
			}
		}
		if(aurkitua) break;
		key2[0]++;
	}

	print_key(key1, 1);
	print_key(key2, 2);
	twodes(DECRYPTION, p5, c1, key1, key2);
	twodes(DECRYPTION, p6, c2, key1, key2);
	twodes(DECRYPTION, p7, c3, key1, key2);
	twodes(DECRYPTION, p8, c4, key1, key2);
	print_plaintext(p5);
	print_plaintext(p6);
	print_plaintext(p7);
	print_plaintext(p8);

	finish = clock();
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
	printf("Time DES: %f seg\n", time_taken);
		
	return 0;
}

void print_plaintext(uint8_t *t){
    char c;
    int i;
    for (i = 0; i < BLOCK_SIZE; i++) {
        c = t[i];
        printf("%c", c);
    }
    printf("\n");
}

void print_key(uint8_t *key, int index){
    int i;
    printf("Key%d: ", index);
    for (i = 0; i < DES_KEY_SIZE; i++) {
        printf("%x ", key[i] & 0xff);
    }
    printf("\n");
}