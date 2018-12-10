package at.favre.lib.crypto.bkdf;

import at.favre.lib.crypto.HKDF;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public interface Version {

    Version HKDF_HMAC512 = new Default(HKDF.fromHmacSha512(), true, (byte) 0x01);
    Version HKDF_HMAC512_BCRYPT_24_BYTE = new Default(HKDF.fromHmacSha512(), false, (byte) 0x02);

    List<Version> VERSIONS = Collections.unmodifiableList(Arrays.asList(HKDF_HMAC512, HKDF_HMAC512_BCRYPT_24_BYTE));

    HKDF getHkdf();

    boolean isUseOnly23ByteBcryptOut();

    byte getVersionCode();

    final class Default implements Version {
        private final HKDF hkdf;
        private final boolean useOnly23ByteBcryptOut;
        private final byte versionCode;

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
    }
}
