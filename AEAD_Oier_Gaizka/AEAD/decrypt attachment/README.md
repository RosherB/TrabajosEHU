AEAD ALGORITHM: AES-128 (*configure library) mode CCM 
IV = 96 bts, T = 128 bits

COMPILE: gcc -o ATTACH_DECRYPT_GCM ATTACH_DECRYPT_GCM.c ../AES/aes.c 

EXECUTE: ./ATTACH_DECRYPT_GCM file.cipher file.tag key_hex output_file.try_different_formats

INPUT DATA: 
- FACTURA_TAG.tag
- FACTURA_IV_CIPHER.cipher
- key = 1e2350aa546771f035478fdf30ee4a2e

