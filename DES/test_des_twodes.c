#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des.h"
 
int main (void)
{
	//DES NORMAL
	printf("\nDES\n");
	unsigned char key[DES_KEY_SIZE]={0x25,0xe5,0x33,0x48,0x36,0x54,0x3f,0x30};
	unsigned char p[BLOCK_SIZE]="Aprobado";
	unsigned char c[BLOCK_SIZE];


	clock_t start, finish;
	double time_taken;
	start = clock();
	printf("Key: "); print_string_hex(key,BLOCK_SIZE);
	printf("Plaintext: "); print_string_hex(p,BLOCK_SIZE); 
	des(ENCRYPTION, p, c, key);
	printf("Ciphertext: "); print_string_hex(c,BLOCK_SIZE);
	des(DECRYPTION, c, p, key);
	printf("new plaintext: "); print_string_hex(p,BLOCK_SIZE);
	
	finish = clock();
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
	printf("Time DES: %f seg\n", time_taken);	
	
	//TWODES
	printf("\n2DES\n");
	uint8_t key1[DES_KEY_SIZE]={0x00,0x00,0x83,0x48,0x42,0x20,0x3f,0x0f}; 
	uint8_t key2[DES_KEY_SIZE]={0x00,0xe5,0x33,0x48,0x36,0x54,0x3f,0x30}; 
	
	start = clock();
	printf("Key: "); print_string_hex(key,BLOCK_SIZE);
	printf("Plaintext: "); print_string_hex(p,BLOCK_SIZE); 
	twodes(ENCRYPTION, p, c, key1, key2);
	printf("Ciphertext: "); print_string_hex(c,BLOCK_SIZE);
	twodes(DECRYPTION, c, p, key1, key2);
	printf("new plaintext: "); print_string_hex(p,BLOCK_SIZE); 
	
	finish = clock();
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
	printf("Time 2DES: %f seg\n", time_taken);

	return 0;
}
