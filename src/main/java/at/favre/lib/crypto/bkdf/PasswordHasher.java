package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public interface PasswordHasher {

    String hash(char[] password, int log_rounds);

    boolean verify(char[] password, String bkdfRefenceHash);

    class Default implements PasswordHasher {
        private final SecureRandom secureRandom;
        private final HKDF hkdf;
        private final byte versionIdentifier;
        private final boolean useOnly23ByteBcryptOut;

        Default(byte versionIdentifier, HKDF hkdf, SecureRandom secureRandom, boolean useOnly23ByteBcryptOut) {
            this.hkdf = hkdf;
            this.versionIdentifier = versionIdentifier;
            this.secureRandom = secureRandom;
            this.useOnly23ByteBcryptOut = useOnly23ByteBcryptOut;
        }

        @Override
        public String hash(char[] password, int log_rounds) {
            byte[] salt16Byte = Bytes.random(16, secureRandom).array();
            BCrypt.HashData data = hashRaw(password, salt16Byte, log_rounds);

            ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + salt16Byte.length + data.rawHash.length);
            buffer.put(versionIdentifier);
            buffer.put((byte) log_rounds);
            buffer.put(salt16Byte); //16 byte
            buffer.put(data.rawHash); //24 byte
            return Bytes.from(buffer).encodeBase64Url();
        }

        private BCrypt.HashData hashRaw(char[] password, byte[] salt16Byte, int log_rounds) {
            if (salt16Byte == null || salt16Byte.length < 16) {
                throw new IllegalArgumentException("invalid salt");
            }

            byte[] pwBytes = Bytes.from(password, StandardCharsets.UTF_8).array();

            byte[] extractedPw = hkdf.extract(null, pwBytes);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[2], useOnly23ByteBcryptOut, true, null, null))
                    .hashRaw(log_rounds, salt16Byte, extractedPw);

            return new BCrypt.HashData(log_rounds, new BCrypt.Version(new byte[]{0x00, versionIdentifier}, useOnly23ByteBcryptOut, true, null, null), salt16Byte, data.rawHash);
        }

        @Override
        public boolean verify(char[] password, String bkdfRefenceHash) {
            BCrypt.HashData data = parse(bkdfRefenceHash);
            BCrypt.HashData referenceHash = hashRaw(password, data.rawSalt, data.cost);
            return Bytes.wrap(referenceHash.rawHash).equalsConstantTime(data.rawHash);
        }

        BCrypt.HashData parse(String bkdfHashBase64) {
            ByteBuffer buffer = Bytes.parseBase64(bkdfHashBase64).buffer();

            byte version = buffer.get();
            byte log_rounds = buffer.get();
            byte[] salt = new byte[16];
            byte[] hash = new byte[(useOnly23ByteBcryptOut ? 23 : 24)];
            buffer.get(salt);
            buffer.get(hash);
            return new BCrypt.HashData(log_rounds, new BCrypt.Version(new byte[]{0x00, version}, useOnly23ByteBcryptOut, true, null, null), salt, hash);
        }
    }

}
