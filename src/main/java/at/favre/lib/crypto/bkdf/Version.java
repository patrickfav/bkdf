package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Encapsulates the information which defines a BKDF version, including code, HKDF version and bcrypt mode
 */
public interface Version {

    int MIN_BCRYPT_HASH_LENGTH_BYTE = 23;
    int MAX_BCRYPT_HASH_LENGTH_BYTE = 24;

    /**
     * Using HKDF-HMAC-SHA512 and 23 byte bcrypt output
     */
    Version HKDF_HMAC512 = new Default(HKDF.fromHmacSha512(), MIN_BCRYPT_HASH_LENGTH_BYTE, (byte) 0x01);

    /**
     * Using HKDF-HMAC-SHA512 and 24 byte bcrypt output
     */
    Version HKDF_HMAC512_BCRYPT_24_BYTE = new Default(HKDF.fromHmacSha512(), MAX_BCRYPT_HASH_LENGTH_BYTE, (byte) 0x02);

    /**
     * List of supported {@link Version}
     */
    List<Version> VERSIONS = Collections.unmodifiableList(Arrays.asList(HKDF_HMAC512, HKDF_HMAC512_BCRYPT_24_BYTE));

    /**
     * The version code used to identify the configuration
     *
     * @return as byte
     */
    byte getVersionCode();

    /**
     * What HKDF version to use (ie. which mac implementation is used)
     *
     * @return HKDF instance
     */
    HKDF getHkdf();

    /**
     * Gets the used bcrypt hash byte length.
     * This is usually 23 or 24 bytes. Choose if you want to use a more compatible approach (using only 23 byte output from bcrypt) or a more correct
     * approach (using the full 24 byte blowfish provides) of using the underlying bcrypt hash.
     *
     * @return length of the used bcrypt hash (23 or 24 byte)
     */
    int getHashByteLength();

    /**
     * Wrapper class for static util methods
     */
    final class Util {
        private Util() {
        }

        /**
         * Get the version model for given code.
         *
         * @param versionCode to check against {@link Version#getVersionCode()}
         * @return version (never null, throws exception)
         * @throws UnsupportedBkdfVersionException if version code is not known
         */
        public static Version getByCode(byte versionCode) {
            for (Version version : VERSIONS) {
                if (version.getVersionCode() == versionCode) {
                    return version;
                }
            }
            throw new UnsupportedBkdfVersionException(versionCode);
        }
    }

    final class Default implements Version {
        private final HKDF hkdf;
        private final int hashByteLength;
        private final byte versionCode;

        @SuppressWarnings("WeakerAccess")
        public Default(HKDF hkdf, int hashByteLength, byte versionCode) {
            if (hashByteLength != MIN_BCRYPT_HASH_LENGTH_BYTE && hashByteLength != MAX_BCRYPT_HASH_LENGTH_BYTE) {
                throw new IllegalArgumentException("hash length must either be " + MIN_BCRYPT_HASH_LENGTH_BYTE + " or " + MAX_BCRYPT_HASH_LENGTH_BYTE);
            }
            this.hkdf = Objects.requireNonNull(hkdf);
            this.hashByteLength = hashByteLength;
            this.versionCode = versionCode;
        }

        @Override
        public HKDF getHkdf() {
            return hkdf;
        }

        @Override
        public int getHashByteLength() {
            return hashByteLength;
        }

        @Override
        public byte getVersionCode() {
            return versionCode;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Default aDefault = (Default) o;
            return hashByteLength == aDefault.hashByteLength &&
                    versionCode == aDefault.versionCode &&
                    Objects.equals(hkdf, aDefault.hkdf);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hkdf, hashByteLength, versionCode);
        }
    }

    /**
     * Thrown if a version code is provided which is not recognized or supported
     */
    @SuppressWarnings("WeakerAccess")
    class UnsupportedBkdfVersionException extends IllegalStateException {
        private final int unsupportedByte;

        /**
         * Create new instance
         *
         * @param unsupportedByte the unsupported version code
         */
        public UnsupportedBkdfVersionException(int unsupportedByte) {
            this.unsupportedByte = unsupportedByte;
        }

        @Override
        public String getMessage() {
            return String.format("Version 0x%s is not supported in this implementation of BKDF", Bytes.from((byte) unsupportedByte).encodeHex());
        }
    }
}
