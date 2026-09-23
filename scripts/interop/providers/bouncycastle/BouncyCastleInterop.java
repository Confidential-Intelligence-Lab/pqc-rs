import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.signers.slhdsa.SLHDSAEngine;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.util.encoders.Hex;

public final class BouncyCastleInterop {
    private BouncyCastleInterop() {}

    private static MLKEMParameters parameters(String name) {
        switch (name) {
        case "ML-KEM-512":
            return MLKEMParameters.ml_kem_512;
        case "ML-KEM-768":
            return MLKEMParameters.ml_kem_768;
        case "ML-KEM-1024":
            return MLKEMParameters.ml_kem_1024;
        default:
            throw new IllegalArgumentException(
                "unsupported ML-KEM parameter set: " + name
            );
        }
    }

    private static byte[] decode(String value) {
        return Hex.decode(value);
    }

    private static String encode(byte[] value) {
        return Hex.toHexString(value);
    }

    private static void requireLength(
        String name,
        byte[] value,
        int expected
    ) {
        if (value.length != expected) {
            throw new IllegalArgumentException(
                name + " must be " + expected + " bytes"
            );
        }
    }

    private static void keygen(
        MLKEMParameters params,
        String dHex,
        String zHex
    ) {
        byte[] d = decode(dHex);
        byte[] z = decode(zHex);

        requireLength("d", d, 32);
        requireLength("z", z, 32);

        byte[] seed = new byte[64];
        System.arraycopy(d, 0, seed, 0, 32);
        System.arraycopy(z, 0, seed, 32, 32);

        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(
            new MLKEMKeyGenerationParameters(
                new FixedSecureRandom(seed),
                params
            )
        );

        AsymmetricCipherKeyPair pair = generator.generateKeyPair();

        MLKEMPublicKeyParameters publicKey =
            (MLKEMPublicKeyParameters)pair.getPublic();

        MLKEMPrivateKeyParameters privateKey =
            (MLKEMPrivateKeyParameters)pair.getPrivate();

        System.out.println(
            encode(publicKey.getEncoded()) + ":" +
            encode(privateKey.getEncoded())
        );
    }

    private static void encaps(
        MLKEMParameters params,
        String publicKeyHex,
        String mHex
    ) {
        byte[] publicKeyBytes = decode(publicKeyHex);
        byte[] m = decode(mHex);

        requireLength("m", m, 32);

        MLKEMPublicKeyParameters publicKey =
            new MLKEMPublicKeyParameters(params, publicKeyBytes);

        SecretWithEncapsulation secret =
            MLKEMGenerator.internalGenerateEncapsulated(publicKey, m);

        try {
            System.out.println(
                encode(secret.getEncapsulation()) + ":" +
                encode(secret.getSecret())
            );
        } finally {
            try {
                secret.destroy();
            } catch (javax.security.auth.DestroyFailedException error) {
                throw new IllegalStateException(
                    "failed to destroy ML-KEM encapsulated secret",
                    error
                );
            }
        }
    }

    private static void decaps(
        MLKEMParameters params,
        String privateKeyHex,
        String ciphertextHex
    ) {
        MLKEMPrivateKeyParameters privateKey =
            new MLKEMPrivateKeyParameters(
                params,
                decode(privateKeyHex)
            );

        try {
            MLKEMExtractor extractor = new MLKEMExtractor(privateKey);
            byte[] sharedSecret =
                extractor.extractSecret(decode(ciphertextHex));

            System.out.println(encode(sharedSecret));
        } finally {
            privateKey.destroy();
        }
    }

    private static SLHDSAParameters slhParameters(String name) {
        switch (name) {
        case "SLH-DSA-SHA2-128s":
            return SLHDSAParameters.sha2_128s;
        case "SLH-DSA-SHA2-128f":
            return SLHDSAParameters.sha2_128f;
        case "SLH-DSA-SHA2-192s":
            return SLHDSAParameters.sha2_192s;
        case "SLH-DSA-SHA2-192f":
            return SLHDSAParameters.sha2_192f;
        case "SLH-DSA-SHA2-256s":
            return SLHDSAParameters.sha2_256s;
        case "SLH-DSA-SHA2-256f":
            return SLHDSAParameters.sha2_256f;
        case "SLH-DSA-SHAKE-128s":
            return SLHDSAParameters.shake_128s;
        case "SLH-DSA-SHAKE-128f":
            return SLHDSAParameters.shake_128f;
        case "SLH-DSA-SHAKE-192s":
            return SLHDSAParameters.shake_192s;
        case "SLH-DSA-SHAKE-192f":
            return SLHDSAParameters.shake_192f;
        case "SLH-DSA-SHAKE-256s":
            return SLHDSAParameters.shake_256s;
        case "SLH-DSA-SHAKE-256f":
            return SLHDSAParameters.shake_256f;
        default:
            throw new IllegalArgumentException(
                "unsupported SLH-DSA parameter set: " + name
            );
        }
    }

    private static void slhKeygen(
        SLHDSAParameters params,
        String seedHex
    ) {
        byte[] seed = decode(seedHex);
        int n = params.getN();
        requireLength("seed", seed, 3 * n);

        byte[] skSeed = java.util.Arrays.copyOfRange(seed, 0, n);
        byte[] skPrf = java.util.Arrays.copyOfRange(seed, n, 2 * n);
        byte[] pkSeed = java.util.Arrays.copyOfRange(seed, 2 * n, 3 * n);

        SLHDSAKeyPairGenerator generator = new SLHDSAKeyPairGenerator();
        generator.init(
            new SLHDSAKeyGenerationParameters(
                new FixedSecureRandom(seed),
                params
            )
        );

        AsymmetricCipherKeyPair pair =
            generator.internalGenerateKeyPair(skSeed, skPrf, pkSeed);

        SLHDSAPublicKeyParameters publicKey =
            (SLHDSAPublicKeyParameters)pair.getPublic();
        SLHDSAPrivateKeyParameters privateKey =
            (SLHDSAPrivateKeyParameters)pair.getPrivate();

        try {
            System.out.println(
                encode(publicKey.getEncoded()) + ":" +
                encode(privateKey.getEncoded())
            );
        } finally {
            privateKey.destroy();
        }
    }

    private static void slhSign(
        SLHDSAParameters params,
        String privateKeyHex,
        String messageHex,
        String contextHex
    ) {
        SLHDSAPrivateKeyParameters privateKey =
            new SLHDSAPrivateKeyParameters(
                params,
                decode(privateKeyHex)
            );

        try {
            SLHDSASigner signer = new SLHDSASigner();
            signer.init(
                true,
                new ParametersWithContext(
                    privateKey,
                    decode(contextHex)
                )
            );

            System.out.println(
                encode(signer.generateSignature(decode(messageHex)))
            );
        } finally {
            privateKey.destroy();
        }
    }

    private static void slhVerify(
        SLHDSAParameters params,
        String publicKeyHex,
        String messageHex,
        String contextHex,
        String signatureHex
    ) {
        SLHDSAPublicKeyParameters publicKey =
            new SLHDSAPublicKeyParameters(
                params,
                decode(publicKeyHex)
            );

        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(
            false,
            new ParametersWithContext(
                publicKey,
                decode(contextHex)
            )
        );

        boolean valid = verifier.verifySignature(
            decode(messageHex),
            decode(signatureHex)
        );

        System.out.println(valid ? "true" : "false");
    }

    private static MLDSAParameters dsaParameters(String name) {
        switch (name) {
        case "ML-DSA-44":
            return MLDSAParameters.ml_dsa_44;
        case "ML-DSA-65":
            return MLDSAParameters.ml_dsa_65;
        case "ML-DSA-87":
            return MLDSAParameters.ml_dsa_87;
        default:
            throw new IllegalArgumentException(
                "unsupported ML-DSA parameter set: " + name
            );
        }
    }

    private static void dsaKeygen(
        MLDSAParameters params,
        String xiHex
    ) {
        byte[] xi = decode(xiHex);
        requireLength("xi", xi, 32);

        MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
        generator.init(
            new MLDSAKeyGenerationParameters(
                new FixedSecureRandom(xi),
                params
            )
        );

        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        MLDSAPublicKeyParameters publicKey =
            (MLDSAPublicKeyParameters)pair.getPublic();
        MLDSAPrivateKeyParameters privateKey =
            (MLDSAPrivateKeyParameters)pair.getPrivate();

        try {
            System.out.println(
                encode(publicKey.getEncoded()) + ":" +
                encode(privateKey.getEncoded())
            );
        } finally {
            privateKey.destroy();
        }
    }

    private static void dsaSign(
        MLDSAParameters params,
        String privateKeyHex,
        String messageHex,
        String contextHex,
        String randomnessHex
    ) throws Exception {
        byte[] privateKeyBytes = decode(privateKeyHex);
        byte[] message = decode(messageHex);
        byte[] context = decode(contextHex);
        byte[] randomness = decode(randomnessHex);

        requireLength("randomness", randomness, 32);

        MLDSAPrivateKeyParameters privateKey =
            new MLDSAPrivateKeyParameters(params, privateKeyBytes);

        try {
            CipherParameters signingParameters =
                new ParametersWithRandom(
                    privateKey,
                    new FixedSecureRandom(randomness)
                );

            signingParameters =
                new ParametersWithContext(
                    signingParameters,
                    context
                );

            MLDSASigner signer = new MLDSASigner();
            signer.init(true, signingParameters);
            signer.update(message, 0, message.length);

            System.out.println(encode(signer.generateSignature()));
        } finally {
            privateKey.destroy();
        }
    }

    private static void dsaVerify(
        MLDSAParameters params,
        String publicKeyHex,
        String messageHex,
        String contextHex,
        String signatureHex
    ) {
        MLDSAPublicKeyParameters publicKey =
            new MLDSAPublicKeyParameters(
                params,
                decode(publicKeyHex)
            );

        MLDSASigner verifier = new MLDSASigner();
        verifier.init(
            false,
            new ParametersWithContext(
                publicKey,
                decode(contextHex)
            )
        );

        byte[] message = decode(messageHex);
        verifier.update(message, 0, message.length);

        boolean valid =
            verifier.verifySignature(decode(signatureHex));

        System.out.println(valid ? "true" : "false");
    }

    private static byte[] hashSlhDigest(
        String prehash,
        byte[] message
    ) {
        org.bouncycastle.crypto.Digest digest;
        int outputLength;

        switch (prehash) {
        case "SHA2-224":
            digest = new SHA224Digest();
            outputLength = 28;
            break;
        case "SHA2-256":
            digest = SHA256Digest.newInstance();
            outputLength = 32;
            break;
        case "SHA2-384":
            digest = new SHA384Digest();
            outputLength = 48;
            break;
        case "SHA2-512":
            digest = new SHA512Digest();
            outputLength = 64;
            break;
        case "SHA2-512/224":
            digest = new SHA512tDigest(224);
            outputLength = 28;
            break;
        case "SHA2-512/256":
            digest = new SHA512tDigest(256);
            outputLength = 32;
            break;
        case "SHA3-224":
            digest = new SHA3Digest(224);
            outputLength = 28;
            break;
        case "SHA3-256":
            digest = new SHA3Digest(256);
            outputLength = 32;
            break;
        case "SHA3-384":
            digest = new SHA3Digest(384);
            outputLength = 48;
            break;
        case "SHA3-512":
            digest = new SHA3Digest(512);
            outputLength = 64;
            break;
        case "SHAKE-128": {
            SHAKEDigest shake = new SHAKEDigest(128);
            shake.update(message, 0, message.length);
            byte[] output = new byte[32];
            shake.doFinal(output, 0, output.length);
            return output;
        }
        case "SHAKE-256": {
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(message, 0, message.length);
            byte[] output = new byte[64];
            shake.doFinal(output, 0, output.length);
            return output;
        }
        default:
            throw new IllegalArgumentException(
                "unsupported HashSLH prehash: " + prehash
            );
        }

        digest.update(message, 0, message.length);
        byte[] output = new byte[outputLength];
        digest.doFinal(output, 0);
        return output;
    }

    private static int hashSlhOidArc(String prehash) {
        switch (prehash) {
        case "SHA2-256":
            return 1;
        case "SHA2-384":
            return 2;
        case "SHA2-512":
            return 3;
        case "SHA2-224":
            return 4;
        case "SHA2-512/224":
            return 5;
        case "SHA2-512/256":
            return 6;
        case "SHA3-224":
            return 7;
        case "SHA3-256":
            return 8;
        case "SHA3-384":
            return 9;
        case "SHA3-512":
            return 10;
        case "SHAKE-128":
            return 11;
        case "SHAKE-256":
            return 12;
        default:
            throw new IllegalArgumentException(
                "unsupported HashSLH prehash: " + prehash
            );
        }
    }

    private static byte[] hashSlhMessagePrime(
        byte[] message,
        byte[] context,
        String prehash
    ) {
        if (context.length > 255) {
            throw new IllegalArgumentException("context too long");
        }

        byte[] digest = hashSlhDigest(prehash, message);

        byte[] oid = new byte[] {
            0x06, 0x09, 0x60, (byte)0x86, 0x48,
            0x01, 0x65, 0x03, 0x04, 0x02,
            (byte)hashSlhOidArc(prehash)
        };

        byte[] output =
            new byte[2 + context.length + oid.length + digest.length];

        int offset = 0;
        output[offset++] = 0x01;
        output[offset++] = (byte)context.length;

        System.arraycopy(
            context, 0, output, offset, context.length
        );
        offset += context.length;

        System.arraycopy(
            oid, 0, output, offset, oid.length
        );
        offset += oid.length;

        System.arraycopy(
            digest, 0, output, offset, digest.length
        );

        return output;
    }

    private static void slhHashSign(
        SLHDSAParameters params,
        String privateKeyHex,
        String messageHex,
        String contextHex,
        String prehash
    ) {
        SLHDSAPrivateKeyParameters privateKey =
            new SLHDSAPrivateKeyParameters(
                params,
                decode(privateKeyHex)
            );

        try {
            byte[] messagePrime = hashSlhMessagePrime(
                decode(messageHex),
                decode(contextHex),
                prehash
            );

            byte[] optRand = privateKey.getPublicSeed();

            byte[] signature =
                SLHDSAEngine.internalGenerateSignature(
                    params,
                    privateKey.getSeed(),
                    privateKey.getPrf(),
                    privateKey.getPublicSeed(),
                    privateKey.getRoot(),
                    null,
                    messagePrime,
                    optRand
                );

            System.out.println(encode(signature));
        } finally {
            privateKey.destroy();
        }
    }

    private static void slhHashVerify(
        SLHDSAParameters params,
        String publicKeyHex,
        String messageHex,
        String contextHex,
        String signatureHex,
        String prehash
    ) {
        SLHDSAPublicKeyParameters publicKey =
            new SLHDSAPublicKeyParameters(
                params,
                decode(publicKeyHex)
            );

        byte[] messagePrime = hashSlhMessagePrime(
            decode(messageHex),
            decode(contextHex),
            prehash
        );

        boolean valid =
            SLHDSAEngine.internalVerifySignature(
                params,
                publicKey.getSeed(),
                publicKey.getRoot(),
                null,
                messagePrime,
                decode(signatureHex)
            );

        System.out.println(valid ? "true" : "false");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: <operation> <parameter-set> [arguments...]"
            );
        }

        String operation = args[0];
        String parameterSet = args[1];

        switch (operation) {
        case "kem-keygen":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-keygen requires d and z"
                );
            }
            keygen(parameters(parameterSet), args[2], args[3]);
            return;

        case "kem-encaps":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-encaps requires public key and m"
                );
            }
            encaps(parameters(parameterSet), args[2], args[3]);
            return;

        case "kem-decaps":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-decaps requires private key and ciphertext"
                );
            }
            decaps(parameters(parameterSet), args[2], args[3]);
            return;

        case "slh-keygen":
            if (args.length != 3) {
                throw new IllegalArgumentException(
                    "slh-keygen requires seed"
                );
            }
            slhKeygen(
                slhParameters(parameterSet),
                args[2]
            );
            return;

        case "slh-sign":
            if (args.length != 5) {
                throw new IllegalArgumentException(
                    "slh-sign requires private key, message, and context"
                );
            }
            slhSign(
                slhParameters(parameterSet),
                args[2],
                args[3],
                args[4]
            );
            return;

        case "slh-verify":
            if (args.length != 6) {
                throw new IllegalArgumentException(
                    "slh-verify requires public key, message, context, and signature"
                );
            }
            slhVerify(
                slhParameters(parameterSet),
                args[2],
                args[3],
                args[4],
                args[5]
            );
            return;

        case "slh-hash-sign":
            if (args.length != 6) {
                throw new IllegalArgumentException(
                    "slh-hash-sign requires private key, message, context, and prehash"
                );
            }
            slhHashSign(
                slhParameters(parameterSet),
                args[2],
                args[3],
                args[4],
                args[5]
            );
            return;

        case "slh-hash-verify":
            if (args.length != 7) {
                throw new IllegalArgumentException(
                    "slh-hash-verify requires public key, message, context, signature, and prehash"
                );
            }
            slhHashVerify(
                slhParameters(parameterSet),
                args[2],
                args[3],
                args[4],
                args[5],
                args[6]
            );
            return;

        case "dsa-keygen":
            if (args.length != 3) {
                throw new IllegalArgumentException(
                    "dsa-keygen requires xi"
                );
            }
            dsaKeygen(
                dsaParameters(parameterSet),
                args[2]
            );
            return;

        case "dsa-sign":
            if (args.length != 6) {
                throw new IllegalArgumentException(
                    "dsa-sign requires private key, message, context, and randomness"
                );
            }
            try {
                dsaSign(
                    dsaParameters(parameterSet),
                    args[2],
                    args[3],
                    args[4],
                    args[5]
                );
            } catch (Exception error) {
                throw new IllegalStateException(
                    "ML-DSA signing failed",
                    error
                );
            }
            return;

        case "dsa-verify":
            if (args.length != 6) {
                throw new IllegalArgumentException(
                    "dsa-verify requires public key, message, context, and signature"
                );
            }
            dsaVerify(
                dsaParameters(parameterSet),
                args[2],
                args[3],
                args[4],
                args[5]
            );
            return;

        default:
            throw new IllegalArgumentException(
                "unsupported operation: " + operation
            );
        }
    }
}
