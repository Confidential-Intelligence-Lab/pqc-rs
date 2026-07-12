#!/usr/bin/env python3
print('# PQC-rs Cryptographic Object Sizes\n')
print('| Parameter set | Public key | Private key | Ciphertext | Shared secret |')
print('|---|---:|---:|---:|---:|')
for row in [('ML-KEM-512',800,1632,768,32),('ML-KEM-768',1184,2400,1088,32),('ML-KEM-1024',1568,3168,1568,32)]:
    print(f'| {row[0]} | {row[1]} B | {row[2]} B | {row[3]} B | {row[4]} B |')
print('\n## Hybrid HPKE\n')
print('| Hybrid KEM | Public key | Private seed | Encapsulation | Shared secret |')
print('|---|---:|---:|---:|---:|')
for row in [('MLKEM768-P256',1249,32,1153,32),('MLKEM768-X25519',1216,32,1120,32),('MLKEM1024-P384',1665,32,1665,32)]:
    print(f'| {row[0]} | {row[1]} B | {row[2]} B | {row[3]} B | {row[4]} B |')
