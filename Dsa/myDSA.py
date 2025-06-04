#!/usr/bin/env python3

import secrets, hashlib

class DSA:
    '''
    Reads and writes DSA keys from/to files (just 1024 bits long).
    The hash of the messages is computed with SHA-1.
    '''
    @classmethod
    def int2hex(cls, num, length=None):
        '''
        Returns a string representing the hexadecimal code of num.
        If length is set, leading zero bytes are added as needed.
        '''
        if length:
            length *= 2
            return '{:0{length}x}'.format(num, length=length)
        else:
            return format(num, 'x')
    
    def __init__(self, p=None, q=None, alpha=None, beta=None, d=None):
        '''
        Sets the initial parameters. The variable names follow the
        nomenclature in the book "Understanding Cryptograhy".
        p and q are the group and subgroup cardinalities.
        alpha is the generator.
        beta is the public/verification key.
        d is the private/signing key.
        '''
        self.p = p
        self.q = q
        self.alpha = alpha
        self.beta = beta
        self.d = d
    
    def read_publickey(self, filename):
        '''
        Read the system parameters and the public/verification key from a
        file.
        '''
        with open(filename, "rb") as f:
            line = f.readline()
            self.p = int(line, 16)
            line = f.readline()
            self.q = int(line, 16)
            line = f.readline()
            self.alpha = int(line, 16)
            line = f.readline()
            self.beta = int(line, 16)

    def read_privatekey(self, filename):
        '''
        Read the private/signing key from a file.
        '''
        with open(filename, "rb") as f:
            line = f.readline()
            self.d = int(line, 16)

    def write_publickey(self, filename):
        '''
        Write the system parameters and the public/verification key to a
        file.
        '''
        if not self.p:
            raise Exception('Cannot write public key. Not set.')
        with open(filename, "wt") as f:
            f.write(self.int2hex(self.p) + '\n')
            f.write(self.int2hex(self.q) + '\n')
            f.write(self.int2hex(self.alpha) + '\n')
            f.write(self.int2hex(self.beta) + '\n')

    def write_privatekey(self, filename):
        '''
        Write the private/signing key to a file.
        '''
        if not self.d:
            raise Exception('Cannot write private key. Not set.')
        with open(filename, "wt") as f:
            f.write(self.int2hex(self.d) + '\n')

    def sign(self, m):
        '''
        Sign a message, m.
        '''
        if not self.d:
            raise Exception('Cannot sign. Private key not set.')
        digest = hashlib.sha1(m).digest()
        h = int.from_bytes(digest, 'big')
        ke = secrets.randbelow(self.q - 1) + 1 # 0 is not a valid key
        r = pow(self.alpha, ke, self.p) % self.q
        s = ((h + self.d*r) * pow(ke, -1, self.q)) % self.q
        
        return (r << 160) + s
    
    def verify(self, m, signature):
        '''
        Verify a signature.
        '''
        if not self.p:
            raise Exception('Cannot verify. Public key not set.')

        # Get r and s from signature
        r = signature >> 160
        
        mask = int.from_bytes(b'\xff' * 20, 'big') # integer with 20 FF bytes
                                                   # equal to (1<<160)-1
        s = signature & mask # Keep just the 20 rightmost bytes
        
        digest = hashlib.sha1(m).digest()
        h = int.from_bytes(digest, 'big')
        sinv = pow(s, -1, self.q)
        u1= (sinv*h)%self.q  
        
        u2=(sinv*r)% self.q     

        bu2 = pow(self.beta,u2, self.p)
        gu1 = pow(self.alpha,u1, self.p)
        bugu = (bu2*gu1)%self.p
        v = bugu%self.q
        print(v , "\n")
 
        return v == r
    
    def getkey(self, signature1 , signature2, m1, m2, r):
        # k = (h(x1)- h(x2)) * (s1 - s2)^-1 mod q
        
        mask = int.from_bytes(b'\xff' * 20, 'big')
        print(int(signature2.rstrip(),16))

        s1 = int(signature1.rstrip(),16) & mask
        s2 = int(signature2.rstrip(),16) & mask

        
        rf = int(r.rstrip(), 16)
        sfinal = (s1 - s2) % self.q
        s = pow(sfinal, -1, self.q)
        
        digest1 = hashlib.sha1(m1).digest()
        h1 = int.from_bytes(digest1, 'big')

        digest2 = hashlib.sha1(m2).digest()
        h2 = int.from_bytes(digest2, 'big')
        
        h = (h1 - h2) % self.q
        k = (h * s) % self.q  


        s1kh = (s1*k - h1) % self.q
        r1 = pow(rf, -1, self.q)
        d = (s1kh*r1) % self.q

        
        return d
        



        
