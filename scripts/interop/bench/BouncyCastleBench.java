import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;

public final class BouncyCastleBench {
    private static final int SAMPLES = 100;
    private static final long TARGET_SAMPLE_NS = 5_000_000L;
    private static final long WARMUP_NS = 5_000_000_000L;

    private static final byte[] MESSAGE =
        "pqc-rfc9958-rs B1.3.5 performance baseline".getBytes();

    private static final byte[] CONTEXT =
        "benchmark".getBytes();

    private static final byte[] KEM_D = fill(32, (byte)0x33);
    private static final byte[] KEM_Z = fill(32, (byte)0x44);
    private static final byte[] KEM_M = fill(32, (byte)0x77);

    private static final byte[] DSA_XI =
        fill(32, (byte)0x65);

    private static final byte[] DSA_RANDOMNESS =
        fill(32, (byte)0x00);

    private static byte[] kemPublicKey;
    private static byte[] kemPrivateKey;
    private static byte[] kemCiphertext;

    private static byte[] dsaPublicKey;
    private static byte[] dsaPrivateKey;
    private static byte[] dsaSignature;

    private static volatile int sink;

    @FunctionalInterface
    private interface Operation {
        void run() throws Exception;
    }

    private static byte[] fill(int n, byte value) {
        byte[] out = new byte[n];
        Arrays.fill(out, value);
        return out;
    }

    private static byte[] kemSeed() {
        byte[] seed = new byte[64];
        System.arraycopy(KEM_D, 0, seed, 0, 32);
        System.arraycopy(KEM_Z, 0, seed, 32, 32);
        return seed;
    }

    private static void kemKeygen() {
        MLKEMKeyPairGenerator generator =
            new MLKEMKeyPairGenerator();

        generator.init(
            new MLKEMKeyGenerationParameters(
                new FixedSecureRandom(kemSeed()),
                MLKEMParameters.ml_kem_768
            )
        );

        AsymmetricCipherKeyPair pair =
            generator.generateKeyPair();

        MLKEMPublicKeyParameters publicKey =
            (MLKEMPublicKeyParameters)pair.getPublic();

        MLKEMPrivateKeyParameters privateKey =
            (MLKEMPrivateKeyParameters)pair.getPrivate();

        try {
            kemPublicKey = publicKey.getEncoded();
            kemPrivateKey = privateKey.getEncoded();

            sink ^= kemPublicKey[0] & 0xff;
            sink ^= kemPrivateKey[0] & 0xff;
        } finally {
            privateKey.destroy();
        }
    }

    private static void kemEncaps() throws Exception {
        MLKEMPublicKeyParameters publicKey =
            new MLKEMPublicKeyParameters(
                MLKEMParameters.ml_kem_768,
                kemPublicKey
            );

        SecretWithEncapsulation secret =
            MLKEMGenerator.internalGenerateEncapsulated(
                publicKey,
                KEM_M
            );

        try {
            kemCiphertext = secret.getEncapsulation();
            byte[] sharedSecret = secret.getSecret();

            sink ^= kemCiphertext[0] & 0xff;
            sink ^= sharedSecret[0] & 0xff;
        } finally {
            secret.destroy();
        }
    }

    private static void kemDecaps() {
        MLKEMPrivateKeyParameters privateKey =
            new MLKEMPrivateKeyParameters(
                MLKEMParameters.ml_kem_768,
                kemPrivateKey
            );

        try {
            MLKEMExtractor extractor =
                new MLKEMExtractor(privateKey);

            byte[] sharedSecret =
                extractor.extractSecret(kemCiphertext);

            sink ^= sharedSecret[0] & 0xff;
        } finally {
            privateKey.destroy();
        }
    }

    private static void dsaKeygen() {
        MLDSAKeyPairGenerator generator =
            new MLDSAKeyPairGenerator();

        generator.init(
            new MLDSAKeyGenerationParameters(
                new FixedSecureRandom(DSA_XI),
                MLDSAParameters.ml_dsa_65
            )
        );

        AsymmetricCipherKeyPair pair =
            generator.generateKeyPair();

        MLDSAPublicKeyParameters publicKey =
            (MLDSAPublicKeyParameters)pair.getPublic();

        MLDSAPrivateKeyParameters privateKey =
            (MLDSAPrivateKeyParameters)pair.getPrivate();

        try {
            dsaPublicKey = publicKey.getEncoded();
            dsaPrivateKey = privateKey.getEncoded();

            sink ^= dsaPublicKey[0] & 0xff;
            sink ^= dsaPrivateKey[0] & 0xff;
        } finally {
            privateKey.destroy();
        }
    }

    private static void dsaSign() throws Exception {
        MLDSAPrivateKeyParameters privateKey =
            new MLDSAPrivateKeyParameters(
                MLDSAParameters.ml_dsa_65,
                dsaPrivateKey
            );

        try {
            CipherParameters parameters =
                new ParametersWithRandom(
                    privateKey,
                    new FixedSecureRandom(DSA_RANDOMNESS)
                );

            parameters =
                new ParametersWithContext(
                    parameters,
                    CONTEXT
                );

            MLDSASigner signer = new MLDSASigner();

            signer.init(true, parameters);
            signer.update(
                MESSAGE,
                0,
                MESSAGE.length
            );

            dsaSignature =
                signer.generateSignature();

            sink ^= dsaSignature[0] & 0xff;
        } finally {
            privateKey.destroy();
        }
    }

    private static void dsaVerify() {
        MLDSAPublicKeyParameters publicKey =
            new MLDSAPublicKeyParameters(
                MLDSAParameters.ml_dsa_65,
                dsaPublicKey
            );

        MLDSASigner verifier = new MLDSASigner();

        verifier.init(
            false,
            new ParametersWithContext(
                publicKey,
                CONTEXT
            )
        );

        verifier.update(
            MESSAGE,
            0,
            MESSAGE.length
        );

        boolean valid =
            verifier.verifySignature(dsaSignature);

        if (!valid) {
            throw new IllegalStateException(
                "ML-DSA verification failed"
            );
        }

        sink ^= 1;
    }

    private static long measure(
        Operation operation,
        long iterations
    ) throws Exception {
        long start = System.nanoTime();

        for (long i = 0; i < iterations; ++i) {
            operation.run();
        }

        return System.nanoTime() - start;
    }

    private static void warmup(
        Operation operation
    ) throws Exception {
        long start = System.nanoTime();

        while (System.nanoTime() - start < WARMUP_NS) {
            operation.run();
        }
    }

    private static long calibrate(
        Operation operation
    ) throws Exception {
        long iterations = 1;

        for (;;) {
            long elapsed =
                measure(operation, iterations);

            if (elapsed >= TARGET_SAMPLE_NS) {
                return iterations;
            }

            if (iterations > (1L << 30)) {
                throw new IllegalStateException(
                    "calibration overflow"
                );
            }

            iterations *= 2;
        }
    }

    private static void benchmark(
        String primitive,
        String name,
        Operation operation
    ) throws Exception {
        /*
         * Keep one JVM alive. Warm this operation before
         * collecting samples so startup/class loading/JIT
         * activity is outside the measured region.
         */
        warmup(operation);

        long iterations = calibrate(operation);

        System.out.println("{");
        System.out.println(
            "  \"provider\": \"bouncycastle\","
        );
        System.out.println(
            "  \"provider_revision\": " +
            "\"ab16374d37c7e18c4090eb8838ebbd72a92593f2\","
        );
        System.out.println(
            "  \"jvm\": \"" +
            System.getProperty("java.version") +
            "\","
        );
        System.out.println(
            "  \"primitive\": \"" +
            primitive +
            "\","
        );
        System.out.println(
            "  \"operation\": \"" +
            name +
            "\","
        );
        System.out.println(
            "  \"samples\": " +
            SAMPLES +
            ","
        );
        System.out.println(
            "  \"iterations_per_sample\": " +
            iterations +
            ","
        );
        System.out.println(
            "  \"sample_ns\": ["
        );

        for (int sample = 0;
             sample < SAMPLES;
             ++sample) {

            long elapsed =
                measure(
                    operation,
                    iterations
                );

            double ns =
                (double)elapsed /
                (double)iterations;

            System.out.printf(
                java.util.Locale.ROOT,
                "    %.6f%s%n",
                ns,
                sample + 1 == SAMPLES
                    ? ""
                    : ","
            );
        }

        System.out.println("  ],");
        System.out.println(
            "  \"sink\": " +
            sink
        );
        System.out.println("}");
    }

    private static void prepare()
        throws Exception {

        kemKeygen();
        kemEncaps();
        kemDecaps();

        dsaKeygen();
        dsaSign();
        dsaVerify();
    }

    public static void main(String[] args)
        throws Exception {

        prepare();

        /*
         * One operation per invocation would restart the JVM.
         * Instead, run all six in this one persistent process.
         *
         * Delimit each JSON object with a marker so the runner
         * can split the resulting stream.
         */

        System.out.println(
            "===BEGIN:kem-keygen==="
        );
        benchmark(
            "ML-KEM-768",
            "kem-keygen",
            BouncyCastleBench::kemKeygen
        );
        System.out.println(
            "===END:kem-keygen==="
        );

        System.out.println(
            "===BEGIN:kem-encaps==="
        );
        benchmark(
            "ML-KEM-768",
            "kem-encaps",
            BouncyCastleBench::kemEncaps
        );
        System.out.println(
            "===END:kem-encaps==="
        );

        System.out.println(
            "===BEGIN:kem-decaps==="
        );
        benchmark(
            "ML-KEM-768",
            "kem-decaps",
            BouncyCastleBench::kemDecaps
        );
        System.out.println(
            "===END:kem-decaps==="
        );

        System.out.println(
            "===BEGIN:dsa-keygen==="
        );
        benchmark(
            "ML-DSA-65",
            "dsa-keygen",
            BouncyCastleBench::dsaKeygen
        );
        System.out.println(
            "===END:dsa-keygen==="
        );

        System.out.println(
            "===BEGIN:dsa-sign==="
        );
        benchmark(
            "ML-DSA-65",
            "dsa-sign",
            BouncyCastleBench::dsaSign
        );
        System.out.println(
            "===END:dsa-sign==="
        );

        System.out.println(
            "===BEGIN:dsa-verify==="
        );
        benchmark(
            "ML-DSA-65",
            "dsa-verify",
            BouncyCastleBench::dsaVerify
        );
        System.out.println(
            "===END:dsa-verify==="
        );
    }
}
