# 2DES MITM (KrA_CrA)

Files in folder:
- des.c, des.h: librery for encryption/decryption with DES and 2DES. The twodes function in des.c is empty.
- test_des_twodes.c: file to undestand the DES library
- MITM.c: file where the meet-in-the-middle attack should be implemented. 
- BFA.c: file where the brute Force attack should be implemented. 

Practical considerations: 
- The DES key has 56 bits (7 bytes), but the key variable of des.c/des.h has 64 bits (8 bytes). 
- Some of the additional bits are to calculate parity and detect errors. 
- These additional bits are the least significant bits or each byte.  
- For example, the least significant bit of key[0] has no effect on the encrypted result. That is, if key[0]=0 or key[0]=1 for example, the result will be the same. 
