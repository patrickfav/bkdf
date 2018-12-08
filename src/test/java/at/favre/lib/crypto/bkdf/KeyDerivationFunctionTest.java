package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class KeyDerivationFunctionTest {

    @Test
    public void testBasicKdf() {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(HKDF.fromHmacSha256(), false);

        char[] pw = "secret".toCharArray();
        int logRounds = 6;
        byte[] salt = Bytes.random(16).array();
        byte[] secretKey = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);

        assertEquals(32, secretKey.length);

        byte[] secretKey2 = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);
        assertArrayEquals(secretKey, secretKey2);
    }
}
