package at.favre.lib.crypto.bkdf;

import java.security.SecureRandom;

/**
 * Main entry point of the BKDF API
 */
@SuppressWarnings("WeakerAccess")
public final class BKDF {

    private BKDF() {
    }

    /**
     * Create a password hasher to use BKDF password hash scheme.
     * Uses default version schema and {@link SecureRandom}
     *
     * @return new instance
     */
    public static PasswordHasher createPasswordHasher() {
        return createPasswordHasher(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom());
    }

    /**
     * Create a password hasher to use BKDF password hash scheme with given config version.
     *
     * @param version used config version
     * @return new instance
     */
    public static PasswordHasher createPasswordHasher(Version version) {
        return createPasswordHasher(version, new SecureRandom());
    }

    /**
     * Create a password hasher to use BKDF password hash scheme with given config version.
     *
     * @param version      used config version
     * @param secureRandom to use for generating entropy for e.g. the salt
     * @return new instance
     */
    public static PasswordHasher createPasswordHasher(Version version, SecureRandom secureRandom) {
        return new PasswordHasher.Default(version, secureRandom);
    }

    /**
     * Create a new instance of password hash verifier.
     * <p>
     * This verifies hashes generated by {@link BKDF#createPasswordHasher()}.
     *
     * @return new instance
     */
    public static PasswordHashVerifier createPasswordHashVerifier() {
        return new PasswordHashVerifier.Default(createPasswordHashUpgrader());
    }

    /**
     * Create a password hasher upgrader, which can be used to upgrade the cost factor of existing password hashes.
     *
     * @return new instance
     */
    public static PasswordHashUpgrader createPasswordHashUpgrader() {
        return createPasswordHashUpgrader(new SecureRandom());
    }

    /**
     * Create a password hasher upgrader, which can be used to upgrade the cost factor of existing password hashes.
     *
     * @param secureRandom to use for generating entropy for e.g. the salt
     * @return new instance
     */
    public static PasswordHashUpgrader createPasswordHashUpgrader(SecureRandom secureRandom) {
        return new PasswordHashUpgrader.Default(secureRandom);
    }

    /**
     * Create a fully usable KDF backed by BCrypt to generate key material for e.g. secret keys.
     *
     * @param version specific protocol version
     * @return new instance
     */
    public static KeyDerivationFunction createKdf(Version version) {
        return new KeyDerivationFunction.Default(version);
    }

    /**
     * Create a fully usable KDF backed by BCrypt to generate key material for e.g. secret keys.
     *
     * @return new instance
     */
    public static KeyDerivationFunction createKdf() {
        return createKdf(Version.HKDF_HMAC512_BCRYPT_24_BYTE);
    }

}
