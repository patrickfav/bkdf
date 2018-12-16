package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;

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
    boolean verify(char[] password, HashData hashData);

    /**
     * Default implementation
     */
    final class Default implements PasswordHashVerifier {
        @Override
        public boolean verify(char[] password, String bkdfRefenceHash) {
            HashData hashData = HashData.parse(bkdfRefenceHash);
            return verify(password, hashData);
        }


        @Override
        public boolean verify(char[] password, HashData bkdfPasswordHashFormat1) {
            PasswordHasher hasher = BKDF.createPasswordHasher(bkdfPasswordHashFormat1.version);
            HashData referenceHash = ((PasswordHasher.Default) hasher).hashRaw(password, bkdfPasswordHashFormat1.rawSalt, bkdfPasswordHashFormat1.cost);
            return Bytes.wrap(referenceHash.rawHash).equalsConstantTime(bkdfPasswordHashFormat1.rawHash);
        }
    }
}
