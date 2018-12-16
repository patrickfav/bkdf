package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Implementation for the BKDF Password Hash protocol used for key stretching of weak user passwords and hash storage.
 */
public interface PasswordHasher {

    /**
     * For given password and cost-factor create password hash.
     * <p>
     * The internal salt will be created automatically with a secure CPRNG. Usually implementations
     * support passing your own implementation of a CPRNG (i.e. {@link SecureRandom}).
     *
     * @param password   from user
     * @param costFactor exponential cost (log2 factor) between 4 and 31 e.g. 12 --&gt;
     *                   2^12 = 4,096 iterations (higher == slower == more secure)
     * @return "BKDF Password Hash Message Format 2" ie. Base64 encoded password hash for storage
     */
    String hash(char[] password, int costFactor);

    /**
     * For given password and cost-factor create password hash.
     * This method will return a more flexible model to be used to either access all the parts of the format
     * or create different message formats from it.
     *
     * @param password   from user
     * @param costFactor exponential cost (log2 factor) between 4 and 31 e.g. 12 --&gt;
     *                   2^12 = 4,096 iterations (higher == slower == more secure)
     * @return password hash in flexible {@link HashData} model
     */
    HashData hashRaw(char[] password, int costFactor);

    /**
     * Default implementation
     */
    final class Default implements PasswordHasher {
        private final SecureRandom secureRandom;
        private final Version version;

        Default(Version version, SecureRandom secureRandom) {
            this.version = version;
            this.secureRandom = secureRandom;
        }

        @Override
        public String hash(char[] password, int costFactor) {
            return hashRaw(password, costFactor).getAsEncodedMessageFormat();
        }

        @Override
        public HashData hashRaw(char[] password, int costFactor) {
            byte[] salt16Byte = Bytes.random(16, secureRandom).array();
            return hashRaw(password, salt16Byte, costFactor);
        }

        HashData hashRaw(char[] password, byte[] salt16Byte, int costFactor) {
            if (salt16Byte == null || salt16Byte.length < 16) {
                throw new IllegalArgumentException("invalid salt");
            }
            if (costFactor < 4 || costFactor > 31) {
                throw new IllegalArgumentException("cost-factor must be between 4 and 31 (same as for bcrypt itself)");
            }

            byte[] pwBytes = Bytes.from(password, StandardCharsets.UTF_8).array();
            return hashRaw(pwBytes, salt16Byte, costFactor);
        }

        HashData hashRaw(byte[] pwBytes, byte[] salt16Byte, int costFactor) {
            byte[] extractedPw = version.getHkdf().extract(null, pwBytes);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[]{0x32, 0x61},
                            version.isUseOnly23ByteBcryptOut(),
                            true, null, null))
                    .hashRaw(costFactor, salt16Byte, extractedPw);

            return new HashData((byte) costFactor, version, salt16Byte, data.rawHash);
        }
    }

}
