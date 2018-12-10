package at.favre.lib.crypto.bkdf;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    @Test
    public void testBasicHasher() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        int logRounds = 6;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);


        PasswordHashVerifier verifier = new PasswordHashVerifier.Default();
        assertTrue(verifier.verify(pw, hash));
    }
}
