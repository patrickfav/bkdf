package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesValidators;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

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

            byte[] extractedPw = version.getHkdf().extract(null, pwBytes);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[]{0x32, 0x61},
                            version.isUseOnly23ByteBcryptOut(),
                            true, null, null))
                    .hashRaw(costFactor, salt16Byte, extractedPw);

            return new HashData((byte) costFactor, version, salt16Byte, data.rawHash);
        }
    }

    /**
     * +
     * Model containing all the parts required for the "BKDF Password Hash Message Format"
     */
    @SuppressWarnings("WeakerAccess")
    final class HashData {
        public final byte cost;
        public final Version version;
        public final byte[] rawSalt;
        public final byte[] rawHash;

        public HashData(byte cost, Version version, byte[] rawSalt, byte[] rawHash) {
            Objects.requireNonNull(rawHash);
            Objects.requireNonNull(rawSalt);
            Objects.requireNonNull(version);
            if (Bytes.wrap(rawSalt).validate(BytesValidators.exactLength(16))
                    && Bytes.wrap(rawHash).validate(BytesValidators
                    .or(BytesValidators.exactLength(23), BytesValidators.exactLength(24)))) {
                this.cost = cost;
                this.version = version;
                this.rawSalt = rawSalt;
                this.rawHash = rawHash;
            } else {
                throw new IllegalArgumentException("salt must be exactly 16 bytes and hash 23/24 bytes long");
            }
        }

        /**
         * Get the "BKDF Password Hash Message Format 1" which is in blob/byte array form
         * <p>
         * Currently this is the following format:
         *
         * <code>V C S S S S S S S S S S S S S S S S H H H H H H H H H H ...</code>
         * <ul>
         * <li>V: 1 byte version code</li>
         * <li>C: 1 byte cost factor</li>
         * <li>S: 16 byte salt</li>
         * <li>H: 23/24 byte hash</li>
         * </ul>
         *
         * @return message as byte array aka "Format 1"
         */
        public byte[] getAsBlobMessageFormat() {
            if (rawHash == null) {
                throw new IllegalStateException("cannot reuse wiped instance");
            }

            ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + rawSalt.length + rawHash.length);
            buffer.put(version.getVersionCode());
            buffer.put(cost);
            buffer.put(rawSalt);
            buffer.put(rawHash);
            return buffer.array();
        }

        /**
         * Get the "BKDF Password Hash Message Format 2" which is a base64-url encoded
         * (rfc4648 "Base 64 Encoding with URL and Filename Safe Alphabet") message containing
         * all information needed to verify a password, including cost factor, version and salt.
         * <p>
         * See  {@link #getAsBlobMessageFormat()} for the exact message format.
         *
         * @return base64-url-safe encoded password hash message aka "Format 2"
         */
        public String getAsEncodedMessageFormat() {
            return Bytes.wrap(getAsBlobMessageFormat()).encodeBase64Url();
        }

        /**
         * Wipe the internal byte arrays for security purposes.
         * This instance must not be used after calling this.
         */
        public void wipe() {
            Bytes.wrapNullSafe(this.rawSalt).mutable().secureWipe();
            Bytes.wrapNullSafe(this.rawHash).mutable().secureWipe();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashData hashData = (HashData) o;
            return cost == hashData.cost &&
                    Objects.equals(version, hashData.version) &&
                    Bytes.wrapNullSafe(rawSalt).equalsConstantTime(hashData.rawSalt) &&
                    Bytes.wrapNullSafe(rawHash).equalsConstantTime(hashData.rawHash);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(cost, version);
            result = 31 * result + Arrays.hashCode(rawSalt);
            result = 31 * result + Arrays.hashCode(rawHash);
            return result;
        }
    }
}
