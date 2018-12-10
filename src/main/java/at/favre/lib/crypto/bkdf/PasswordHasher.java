package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public interface PasswordHasher {

    String hash(char[] password, int log_rounds);

    class Default implements PasswordHasher {
        private final SecureRandom secureRandom;
        private final HKDF hkdf;
        private final byte versionCode;
        private final boolean useOnly23ByteBcryptOut;

        Default(Version version, SecureRandom secureRandom) {
            this.hkdf = version.getHkdf();
            this.versionCode = version.getVersionCode();
            this.useOnly23ByteBcryptOut = version.isUseOnly23ByteBcryptOut();
            this.secureRandom = secureRandom;
        }

        @Override
        public String hash(char[] password, int log_rounds) {
            byte[] salt16Byte = Bytes.random(16, secureRandom).array();
            BCrypt.HashData data = hashRaw(password, salt16Byte, log_rounds);

            ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + salt16Byte.length + data.rawHash.length);
            buffer.put(versionCode);
            buffer.put((byte) log_rounds);
            buffer.put(salt16Byte); //16 byte
            buffer.put(data.rawHash); //24 byte
            return Bytes.from(buffer).encodeBase64Url();
        }

        BCrypt.HashData hashRaw(char[] password, byte[] salt16Byte, int log_rounds) {
            if (salt16Byte == null || salt16Byte.length < 16) {
                throw new IllegalArgumentException("invalid salt");
            }

            byte[] pwBytes = Bytes.from(password, StandardCharsets.UTF_8).array();

            byte[] extractedPw = hkdf.extract(null, pwBytes);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[2], useOnly23ByteBcryptOut, true, null, null))
                    .hashRaw(log_rounds, salt16Byte, extractedPw);

            return new BCrypt.HashData(log_rounds, new BCrypt.Version(new byte[]{0x00, versionCode}, useOnly23ByteBcryptOut, true, null, null), salt16Byte, data.rawHash);
        }
    }
}
