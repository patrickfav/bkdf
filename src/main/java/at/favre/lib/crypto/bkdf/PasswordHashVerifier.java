package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;

/**
 * Class which can verify BKDF hash message format password hashes
 */
public interface PasswordHashVerifier {

    /**
     * Verify a given type 2 format message (encoded as base64) and given user password
     *
     * @param password                from user
     * @param bkdfPasswordHashFormat2 "BKDF Password Hash Message Format 2" ie. Base64 encoded password hash for storage,
     *                                see {@link PasswordHasher#hash(char[], int)};
     * @return true iff given password matches given password hash, false otherwise
     */
    boolean verify(char[] password, String bkdfPasswordHashFormat2);

    /**
     * Verify a given password hash and given user password
     *
     * @param password from user
     * @param hashData format-less bkdf hash format, see {@link PasswordHasher#hashRaw(char[], int)}
     * @return true iff given password matches given password hash, false otherwise
     */
    boolean verify(char[] password, PasswordHasher.HashData hashData);

    /**
     * Default implementation
     */
    final class Default implements PasswordHashVerifier {
        @Override
        public boolean verify(char[] password, String bkdfRefenceHash) {
            PasswordHasher.HashData hashData = parse(bkdfRefenceHash);
            return verify(password, hashData);
        }

        private PasswordHasher.HashData parse(String bkdfRefenceHash) {
            ByteBuffer buffer = Bytes.parseBase64(bkdfRefenceHash).buffer();

            byte versionByte = buffer.get();
            Version version = Version.Util.getByCode(versionByte);

            byte costFactor = buffer.get();
            byte[] salt = new byte[16];
            byte[] hash = new byte[(version.isUseOnly23ByteBcryptOut() ? 23 : 24)];
            buffer.get(salt);
            buffer.get(hash);
            return new PasswordHasher.HashData(costFactor, version, salt, hash);
        }

        @Override
        public boolean verify(char[] password, PasswordHasher.HashData bkdfPasswordHashFormat1) {
            PasswordHasher hasher = BKDF.createPasswordHasher(bkdfPasswordHashFormat1.version);
            PasswordHasher.HashData referenceHash = ((PasswordHasher.Default) hasher).hashRaw(password, bkdfPasswordHashFormat1.rawSalt, bkdfPasswordHashFormat1.cost);
            return Bytes.wrap(referenceHash.rawHash).equalsConstantTime(bkdfPasswordHashFormat1.rawHash);
        }
    }
}
