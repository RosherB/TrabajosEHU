#!/usr/bin/env python3

import os
from myDSA import DSA

FILES_PATH='files'
PUBLICKEY_FILENAME='public'
SIGNATURES_FILENAME='signatures'

def main():
    dsa = DSA()
    dsa.read_publickey(PUBLICKEY_FILENAME)
    filenames, signatures = read_signatures(SIGNATURES_FILENAME)

    for filename, signature in zip(filenames, signatures):
        with open(os.path.join(FILES_PATH, filename), "rb") as f:
            data = f.read()
            print(signature, "signature")
            if dsa.verify(data, signature):
                print(f'[{filename}]: Valid signature.')
            else:
                print(f'[{filename}]: Invalid signature.')

    key1 = "01e07fa604a92ee7db5f76fffc28bafd04fd2ade4770fc8f5aace15acddddb50f96f4d22fd928952"
    key2 = "01e07fa604a92ee7db5f76fffc28bafd04fd2ade621b8af3f6334c3dff77a56323cb0b06c6af929a"
    r = "01e07fa604a92ee7db5f76fffc28bafd04fd2ade"

    with open(os.path.join(FILES_PATH, 'ipsum.txt'), "rb") as f:
            m1 = f.read()
    with open(os.path.join(FILES_PATH, 'lorem.txt'), "rb") as f:
            m2 = f.read()
    
    
    d = dsa.getkey(key1, key2, m1, m2, r)

    dsa.d = d

    original_signature = int(key1, 16)

    signature_test = dsa.sign(m1)

    if dsa.verify(m1, signature_test):
        print("d egokia da")
    else:
        print("d ez da egokia")

def read_signatures(filename):
    filenames = []
    signatures = []
    with open(filename, "rt") as f:
        lines = f.readlines()
    for filename, signature in zip(lines[0::2], lines[1::2]):
        filenames.append(filename.rstrip())
        signatures.append(int(signature.rstrip(), 16))

    return filenames, signatures

if __name__ == '__main__':
    main()
