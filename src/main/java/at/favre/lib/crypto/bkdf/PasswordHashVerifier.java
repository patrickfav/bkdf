package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.ByteBuffer;

public interface PasswordHashVerifier {

    boolean verify(char[] password, String bkdfRefenceHash);

    final class Default implements PasswordHashVerifier {
        @Override
        public boolean verify(char[] password, String bkdfRefenceHash) {

            ByteBuffer buffer = Bytes.parseBase64(bkdfRefenceHash).buffer();

            byte versionByte = buffer.get();

            for (Version version : Version.VERSIONS) {
                if (version.getVersionCode() == versionByte) {

                    byte log_rounds = buffer.get();
                    byte[] salt = new byte[16];
                    byte[] hash = new byte[(version.isUseOnly23ByteBcryptOut() ? 23 : 24)];
                    buffer.get(salt);
                    buffer.get(hash);

                    PasswordHasher hasher = BKDF.createPasswordHasher(version);
                    BCrypt.HashData referenceHash = ((PasswordHasher.Default) hasher).hashRaw(password, salt, log_rounds);
                    return Bytes.wrap(referenceHash.rawHash).equalsConstantTime(hash);
                }
            }

            throw new UnsupportedBkdfVersionException(versionByte);
        }
    }

    class UnsupportedBkdfVersionException extends IllegalStateException {
        private final int unsupportedByte;

        public UnsupportedBkdfVersionException(int unsupportedByte) {
            this.unsupportedByte = unsupportedByte;
        }

        @Override
        public String getMessage() {
            return String.format("Version %d is not supported in this implementation of BKDF", unsupportedByte);
        }
    }
}
