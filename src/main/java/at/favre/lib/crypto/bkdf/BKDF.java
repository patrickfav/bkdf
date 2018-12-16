package at.favre.lib.crypto.bkdf;

import java.security.SecureRandom;

public final class BKDF {

    private BKDF() {
    }

    public static PasswordHasher createPasswordHasher() {
        return createPasswordHasher(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom());
    }

    public static PasswordHasher createPasswordHasher(Version version) {
        return createPasswordHasher(version, new SecureRandom());
    }

    public static PasswordHasher createPasswordHasher(Version version, SecureRandom secureRandom) {
        return new PasswordHasher.Default(version, secureRandom);
    }

    public static PasswordHashVerifier createPasswordHashVerifier() {
        return new PasswordHashVerifier.Default(createPasswordHashUpgrader());
    }

    public static PasswordHashUpgrader createPasswordHashUpgrader() {
        return createPasswordHashUpgrader(new SecureRandom());
    }

    public static PasswordHashUpgrader createPasswordHashUpgrader(SecureRandom secureRandom) {
        return new PasswordHashUpgrader.Default(secureRandom);
    }

    public static KeyDerivationFunction createKdf(Version version) {
        return new KeyDerivationFunction.Default(version);
    }

    public static KeyDerivationFunction createKdf() {
        return createKdf(Version.HKDF_HMAC512_BCRYPT_24_BYTE);
    }

}
