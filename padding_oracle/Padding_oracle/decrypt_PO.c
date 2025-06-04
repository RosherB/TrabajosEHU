
#include "AES_CBC.h"

int main(void)
{
	uint8_t cor;
	uint32_t clen,plen;
	int j, k, i;

	uint8_t* ciphertext_hex = "60592ff65e192e29a29be678fc8873cd0aabea229e2d4521568b1fa32712a1fd8037b482bbc8f3bc523ad5e2e2fd0868";
	clen = strlen(ciphertext_hex)/2;
	
	uint8_t* ciphertext = malloc(clen*sizeof(uint8_t));
	uint8_t* intermediate = malloc(clen*sizeof(uint8_t));
	uint8_t* p_xor = malloc(clen*sizeof(uint8_t));
	uint8_t desired_p[16] = {'G','A','I','Z','K','A',' ','C','E','R','E','Z','O',3,3,3};
	parse(clen, ciphertext_hex, ciphertext);

	printf("Ciphertext (hex): "); 
	print_hex(ciphertext,clen);
	uint8_t* plaintext = malloc(plen*sizeof(uint8_t));

	uint8_t ignore = ciphertext[31];

	for (i = 0; i < 16; i++){
		for (j = 0; j < 256; j++){
			if (i == 0 && (uint8_t) j == ignore) continue;
			ciphertext[31-i] = (uint8_t) j;
			plen = decipher_AES_CBC_PO(plaintext, ciphertext, clen);

			if (plen!=0){
				intermediate[47-i] = ciphertext[31-i] ^ (i+1);
				if (i < 15)
				for (k = 0; k < i+1; k++){
					ciphertext[31-k] = (i+2) ^ intermediate[47-k];
				}
				break;
			}	
		}
	}
	
	printf("intermediate[32-47] (hex): "); 
	print_hex(&intermediate[32],16);

	for (i = 0; i < 16; i++){
		ciphertext[i+16] = desired_p[i] ^ intermediate[32+i];
	}

	plen = decipher_AES_CBC_PO(plaintext, ciphertext, clen);

	if (plen != 0){
		uint32_t offset=32;
		printf("Your name: "); 
		print_c(plaintext+offset, plen-offset);	
	}
	
		
	free(ciphertext); 
	free(plaintext);
	free(intermediate);	
	return(0);
}
