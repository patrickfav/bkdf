package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class KeyDerivationFunctionTest {

    @Test
    public void testBasicKdfPw() {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);

        char[] pw = "secret1234 !_".toCharArray();
        int logRounds = 4;
        byte[] salt = Bytes.random(16).array();
        byte[] secretKey = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);

        assertEquals(32, secretKey.length);

        byte[] secretKey2 = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);
        assertArrayEquals(secretKey, secretKey2);
    }

    @Test
    public void testBasicKdfByteArray() {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);

        byte[] pw = Bytes.from("secret1234 !_".toCharArray()).array();
        int logRounds = 4;
        byte[] salt = Bytes.random(16).array();
        byte[] secretKey = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);

        assertEquals(32, secretKey.length);

        byte[] secretKey2 = kdf.derive(salt, pw, logRounds, Bytes.from("aes-key").array(), 32);
        assertArrayEquals(secretKey, secretKey2);
    }

    @Test
    public void testBasicMultiKdf() {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);

        char[] pw = "secret1234 !_".toCharArray();
        int logRounds = 5;
        byte[] salt = Bytes.random(16).array();

        List<KeyDerivationFunction.KdfConfig> configList = Arrays.asList(
                new KeyDerivationFunction.KdfConfig(Bytes.from("aes-key").array(), 16),
                new KeyDerivationFunction.KdfConfig(Bytes.from("mac-key").array(), 32)
        );
        List<byte[]> secretKeyList = kdf.deriveMulti(salt, Bytes.from(pw).array(), logRounds, configList);
        assertEquals(2, secretKeyList.size());
        assertEquals(16, secretKeyList.get(0).length);
        assertEquals(32, secretKeyList.get(1).length);
    }
}
