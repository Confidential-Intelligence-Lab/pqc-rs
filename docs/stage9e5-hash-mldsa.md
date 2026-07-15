# Stage 9E-5: HashML-DSA ACVP Validation

Implements FIPS 204 Algorithms 4 and 5 using:

`M' = 0x01 || len(ctx) || ctx || DER(OID(PH)) || PH(M)`

Supports all ACVP SHA-2, SHA-3, SHAKE-128, and SHAKE-256 identifiers.
Only external `preHash=preHash` AFT groups are processed.
