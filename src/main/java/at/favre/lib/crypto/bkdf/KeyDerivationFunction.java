package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Key Derivation protocol of BKDF. Used for derived high entropy secret keys from user passwords with a given cost factor.
 * <p>
 * Alternatives include:
 * <ul>
 * <li>PBKDF2</li>
 * <li>scrypt</li>
 * <li>Argon2</li>
 * </ul>
 */
@SuppressWarnings("WeakerAccess")
public interface KeyDerivationFunction {

    /**
     * Derive high entropy key material from given salt, user password.
     * <p>
     * The output key material can be used as secret key like that:
     *
     * <pre>
     *     byte[] okm = kdf.derive(...);
     *     SecretKey secretKey = new SecretKeySpec(okm,"AES");
     * </pre>
     * <p>
     * This will create a AES key from the <code>okm</code> (output key material).
     *
     * @param salt          at least 16 byte long nonce (number used once); salt is not required to be secret
     * @param password      user provided password
     * @param costFactor    exponential cost (log2 factor) between 4 and 31 e.g. 12 --&gt;
     *                      2^12 = 4,096 iterations (higher == slower == more secure)
     * @param infoParam     optional parameter that can be used to pin the key material to a specific context (e.g.
     *                      creating a MAC and AES key from same password, just pass <code>"mac".getBytes()</code> and
     *                      <code>"aes".getBytes()</code> as parameter. Can be null.
     * @param outLengthByte how many bytes long the resulting key material should be (usually 16 or 32 bytes)
     * @return raw output key material
     */
    byte[] derive(byte[] salt, char[] password, int costFactor, byte[] infoParam, int outLengthByte);

    /**
     * Derive high entropy key material from given salt, user password.
     * <p>
     * The output key material can be used as secret key like that:
     *
     * <pre>
     *     byte[] okm = kdf.derive(...);
     *     SecretKey secretKey = new SecretKeySpec(okm,"AES");
     * </pre>
     * <p>
     * This will create a AES key from the <code>okm</code> (output key material).
     *
     * @param salt          at least 16 byte long nonce (number used once); salt is not required to be secret
     * @param ikm           user provided password as byte array or other password reheated entropy
     * @param costFactor    exponential cost (log2 factor) between 4 and 31 e.g. 12 --&gt;
     *                      2^12 = 4,096 iterations (higher == slower == more secure)
     * @param infoParam     optional parameter that can be used to pin the key material to a specific context (e.g.
     *                      creating a MAC and AES key from same password, just pass <code>"mac".getBytes()</code> and
     *                      <code>"aes".getBytes()</code> as parameter. Can be null.
     * @param outLengthByte how many bytes long the resulting key material should be (usually 16 or 32 bytes)
     * @return raw output key material
     */
    byte[] derive(byte[] salt, byte[] ikm, int costFactor, byte[] infoParam, int outLengthByte);

    /**
     * Derive multiple high entropy key material from given salt, user password.
     * Use this to more efficiently calculate multiple output key materials with a single call. This will only
     * calculate the expensive key stretching function only once for all outputs.
     * <p>
     * The output key material can be used as secret key like that:
     *
     * <pre>
     *     List<byte[]> okmList = kdf.derive(...);
     *     SecretKey secretKey = new SecretKeySpec(okmList.get(0),"AES");
     * </pre>
     * <p>
     * This will create a AES key from the <code>okm</code> (output key material).
     *
     * @param salt       at least 16 byte long nonce (number used once); salt is not required to be secret
     * @param ikm        user provided password as byte array or other password reheated entropy
     * @param costFactor exponential cost (log2 factor) between 4 and 31 e.g. 12 --&gt;
     *                   2^12 = 4,096 iterations (higher == slower == more secure)
     * @param configList list of infoParam and outLengths; for every entry this will create an output okm entry
     * @return list of okm (output key material) with the same size and order as configList
     */
    List<byte[]> deriveMulti(byte[] salt, byte[] ikm, int costFactor, List<KdfConfig> configList);

    /**
     * Default implementation
     */
    final class Default implements KeyDerivationFunction {
        private static final byte[] FIXED_INFO_PARAM = Bytes.from("bkdf").array();

        private final HKDF hkdf;
        private final boolean useOnly23ByteBcryptOut;

        public Default(Version version) {
            this.hkdf = version.getHkdf();
            this.useOnly23ByteBcryptOut = version.isUseOnly23ByteBcryptOut();
        }

        @Override
        public byte[] derive(byte[] salt, char[] password, int costFactor, byte[] infoParam, int outLengthByte) {
            return derive(salt, Bytes.from(password, StandardCharsets.UTF_8).array(), costFactor, infoParam, outLengthByte);
        }

        @Override
        public byte[] derive(byte[] salt, byte[] ikm, int costFactor, byte[] infoParam, int outLengthByte) {
            return deriveMulti(salt, ikm, costFactor,
                    Collections.singletonList(new KdfConfig(infoParam, outLengthByte))).get(0);
        }

        @Override
        public List<byte[]> deriveMulti(byte[] salt, byte[] ikm, int costFactor, List<KdfConfig> configList) {
            if (Objects.requireNonNull(configList).isEmpty()) {
                throw new IllegalArgumentException("config list must not be empty");
            }

            byte[] extractedPw = hkdf.extract(null, ikm);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[]{0x32, 0x61},
                            useOnly23ByteBcryptOut,
                            true, null, null))
                    .hashRaw(costFactor, salt, extractedPw);

            List<byte[]> outList = new ArrayList<>(configList.size());
            for (KdfConfig kdfConfig : configList) {
                outList.add(hkdf.expand(data.rawHash, Bytes.wrapNullSafe(kdfConfig.infoParam).append(FIXED_INFO_PARAM).array(), kdfConfig.outLengthByte));
            }
            return outList;
        }
    }

    /**
     * Wraps some of the needed configs for use in KDF
     */
    final class KdfConfig {
        public final byte[] infoParam;
        public final int outLengthByte;

        /**
         * Create new instance.
         *
         * @param infoParam     optional parameter that can be used to pin the key material to a specific context (e.g.
         *                      creating a MAC and AES key from same password, just pass <code>"mac".getBytes()</code>
         *                      and <code>"aes".getBytes()</code> as parameter. Can be null.
         * @param outLengthByte how many bytes long the resulting key material should be (usually 16 or 32 bytes)
         */
        public KdfConfig(byte[] infoParam, int outLengthByte) {
            this.infoParam = infoParam;
            this.outLengthByte = outLengthByte;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            KdfConfig kdfConfig = (KdfConfig) o;
            return outLengthByte == kdfConfig.outLengthByte &&
                    Arrays.equals(infoParam, kdfConfig.infoParam);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(outLengthByte);
            result = 31 * result + Arrays.hashCode(infoParam);
            return result;
        }
    }
}
