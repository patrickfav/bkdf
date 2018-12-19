package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.testdata.KdfTestData;
import at.favre.lib.crypto.bkdf.util.TestCaseKdf;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class KeyDerivationFunctionTest {
    private KeyDerivationFunction kdf;

    @Before
    public void setup() {
        kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);
    }

    @Test
    public void testBasicKdfPw() {
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

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveMultiNoConfig() {
        kdf.deriveMulti(Bytes.random(16).array(), Bytes.random(32).array(), 4, Collections.<KeyDerivationFunction.KdfConfig>emptyList());
    }

    @Test
    public void testGetHashVersion() {
        assertEquals(Version.HKDF_HMAC512, new KeyDerivationFunction.Default(Version.HKDF_HMAC512).getHashVersion());
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new KeyDerivationFunction.Default(Version.HKDF_HMAC512_BCRYPT_24_BYTE).getHashVersion());
    }

    @Test
    public void testKdfConfig() {
        KeyDerivationFunction.KdfConfig k1 = new KeyDerivationFunction.KdfConfig(new byte[9], 15);
        KeyDerivationFunction.KdfConfig k2 = new KeyDerivationFunction.KdfConfig(new byte[9], 15);

        assertEquals(k1, k2);
        assertEquals(k1.hashCode(), k2.hashCode());

        KeyDerivationFunction.KdfConfig k3 = new KeyDerivationFunction.KdfConfig(new byte[9], 16);

        assertNotEquals(k1, k3);
        assertNotEquals(k1.hashCode(), k3.hashCode());

        assertEquals(15, k1.outLengthByte);
        assertArrayEquals(new byte[9], k1.infoParam);
    }

    @Test
    public void testVerifyReferenceTest1() {
        testVerifyReferenceTest(Version.HKDF_HMAC512, KdfTestData.TEST_DATA_V1_72_OUT);
    }

    @Test
    public void testVerifyReferenceTest2() {
        testVerifyReferenceTest(Version.HKDF_HMAC512_BCRYPT_24_BYTE, KdfTestData.TEST_DATA_V2_72_OUT);
    }

    @Test
    public void testVerifyReferenceTest3() {
        testVerifyReferenceTest(Version.HKDF_HMAC512, KdfTestData.TEST_DATA_V1_16_OUT);
    }

    private void testVerifyReferenceTest(Version version, TestCaseKdf[] data) {
        KeyDerivationFunction kdf = BKDF.createKdf(version);
        for (TestCaseKdf testCase : data) {
            byte[] okm = kdf.derive(testCase.salt, testCase.password, testCase.cost, testCase.info, testCase.outLength);
            assertArrayEquals(testCase.hash, okm);
        }
    }
}
