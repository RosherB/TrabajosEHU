ENCRYPT-THEN-MAC (ISO/IEC 19772:2009)
Encrypt algorithm: AES-128 (*configure AES library) mode CBC 
Integrity algorithm: HMAC with SHA-256 (T = 128 bits)

COMPILE: gcc -o CHAT_DECRYPT_THEN_HMAC CHAT_DECRYPT_THEN_HMAC.c ../AES/aes.c ../SHA256/sha256.c

EXECUTE: ./CHAT_DECRYPT_THEN_HMAC file.cipher key_encrypt_hex key_HMAC_hex

INPUT DATA: 
- CHAT_IV_CIPHER_HMAC.cipher (concat of: iv, c, HMAC)
- key_encrypt = ce44250a450433fe25a75f613ed7aa03
- key_HMAC = fe0431ed135846f0859143100e0bfe23



