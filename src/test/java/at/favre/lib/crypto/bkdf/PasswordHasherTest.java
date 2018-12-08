package at.favre.lib.crypto.bkdf;

import at.favre.lib.crypto.HKDF;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    @Test
    public void testBasicHasher() {
        PasswordHasher hasher = new PasswordHasher.Default((byte) 64, HKDF.fromHmacSha256(), new SecureRandom(), false);
        char[] pw = "secret".toCharArray();
        int logRounds = 6;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        assertTrue(hasher.verify(pw, hash));
    }
}
