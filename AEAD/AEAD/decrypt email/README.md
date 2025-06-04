AEAD ALGORITHM: AES-128 (*configure AES library) mode CCM 
T = 64 bits, nonce = 32 bits

COMPILE: gcc -o EMAIL_DECRYPT_CCM EMAIL_DECRYPT_CCM.c ../AES/aes.c

EXECUTE: ./EMAIL_DECRYPT_CCM file.cipher associated_data_file.txt key_hex

INPUT DATA: 
- EMAIL_ASSOCIATED_DATA.txt 
- EMAIL_NONCE_CIPHER.cipher (concat of: nonce, c)
- key = 1e2350aa546771f035478fdf30ee4a2e
