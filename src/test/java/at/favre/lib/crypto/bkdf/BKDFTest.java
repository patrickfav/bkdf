package at.favre.lib.crypto.bkdf;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class BKDFTest {

    @Test
    public void testCreateDefaultPasswordHasher() {
        PasswordHasher hasher = BKDF.createPasswordHasher();
        assertNotNull(hasher);
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, hasher.getHashVersion());
    }

    @Test
    public void testCreateVersionPasswordHasher() {
        PasswordHasher hasher = BKDF.createPasswordHasher(Version.HKDF_HMAC512);
        assertNotNull(hasher);
        assertEquals(Version.HKDF_HMAC512, hasher.getHashVersion());
    }

    @Test
    public void testCreateVersionSecureRandomPasswordHasher() {
        PasswordHasher hasher = BKDF.createPasswordHasher(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom());
        assertNotNull(hasher);
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, hasher.getHashVersion());
    }

    @Test
    public void testCreatePasswordHasherVerifier() {
        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertNotNull(verifier);
    }

    @Test
    public void testCreatePasswordHasherUpgrader() {
        PasswordHashUpgrader upgrader = BKDF.createPasswordHashUpgrader();
        assertNotNull(upgrader);

        upgrader = BKDF.createPasswordHashUpgrader(new SecureRandom());
        assertNotNull(upgrader);
    }

    @Test
    public void testCreateKdf() {
        KeyDerivationFunction kdf = BKDF.createKdf();
        assertNotNull(kdf);
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, kdf.getHashVersion());

        kdf = BKDF.createKdf(Version.HKDF_HMAC512);
        assertNotNull(kdf);
        assertEquals(Version.HKDF_HMAC512, kdf.getHashVersion());
    }
}
