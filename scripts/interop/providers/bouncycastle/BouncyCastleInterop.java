import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
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

    public static void main(String[] args) {
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: <operation> <parameter-set> [arguments...]"
            );
        }

        String operation = args[0];
        MLKEMParameters params = parameters(args[1]);

        switch (operation) {
        case "kem-keygen":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-keygen requires d and z"
                );
            }
            keygen(params, args[2], args[3]);
            return;

        case "kem-encaps":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-encaps requires public key and m"
                );
            }
            encaps(params, args[2], args[3]);
            return;

        case "kem-decaps":
            if (args.length != 4) {
                throw new IllegalArgumentException(
                    "kem-decaps requires private key and ciphertext"
                );
            }
            decaps(params, args[2], args[3]);
            return;

        default:
            throw new IllegalArgumentException(
                "unsupported operation: " + operation
            );
        }
    }
}
