package at.favre.lib.crypto.bkdf;

import at.favre.lib.crypto.HKDF;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Encapsulates the information which defines a BKDF version, including code, HKDF version and bcrypt mode
 */
public interface Version {

    /**
     * Using HKDF-HMAC-SHA512 and 23 byte bcrypt output
     */
    Version HKDF_HMAC512 = new Default(HKDF.fromHmacSha512(), true, (byte) 0x01);

    /**
     * Using HKDF-HMAC-SHA512 and 24 byte bcrypt output
     */
    Version HKDF_HMAC512_BCRYPT_24_BYTE = new Default(HKDF.fromHmacSha512(), false, (byte) 0x02);

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
     * Choose if you want to use a more compatible approach (using only 23 byte output from bcrypt) or a more correct
     * approach (using the full 24 byte blowfish provides) of using the underlying bcrypt hash.
     *
     * @return true iff only 23 and not 24 byte of the bcrypt hash is used
     */
    boolean isUseOnly23ByteBcryptOut();

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
        private final boolean useOnly23ByteBcryptOut;
        private final byte versionCode;

        @SuppressWarnings("WeakerAccess")
        public Default(HKDF hkdf, boolean useOnly23ByteBcryptOut, byte versionCode) {
            this.hkdf = hkdf;
            this.useOnly23ByteBcryptOut = useOnly23ByteBcryptOut;
            this.versionCode = versionCode;
        }

        @Override
        public HKDF getHkdf() {
            return hkdf;
        }

        @Override
        public boolean isUseOnly23ByteBcryptOut() {
            return useOnly23ByteBcryptOut;
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
            return useOnly23ByteBcryptOut == aDefault.useOnly23ByteBcryptOut &&
                    versionCode == aDefault.versionCode &&
                    Objects.equals(hkdf, aDefault.hkdf);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hkdf, useOnly23ByteBcryptOut, versionCode);
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
            return String.format("Version %d is not supported in this implementation of BKDF", unsupportedByte);
        }
    }
}
