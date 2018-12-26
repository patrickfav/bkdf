package at.favre.lib.crypto.bkdf;

import at.favre.lib.crypto.bkdf.testdata.PasswordHashTestData;
import at.favre.lib.crypto.bkdf.util.TestCaseHasher;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {
    private PasswordHasher hasher;

    @Before
    public void setup() {
        hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
    }

    @Test
    public void testBasicHasher() {
        char[] pw = "secret".toCharArray();
        int logRounds = 6;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));
    }

    @Test
    public void testVerifyReferenceTest1() {
        testVerifyReferenceTest(PasswordHashTestData.TEST_DATA_V1);
    }

    @Test
    public void testVerifyReferenceTest2() {
        testVerifyReferenceTest(PasswordHashTestData.TEST_DATA_V2);
    }

    private void testVerifyReferenceTest(TestCaseHasher[] data) {
        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        for (TestCaseHasher testCase : data) {
            assertTrue(verifier.verify(testCase.password, testCase.hash));
        }
    }

    @Test
    public void testGetHashVersion() {
        assertEquals(Version.HKDF_HMAC512, new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom()).getHashVersion());
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new PasswordHasher.Default(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom()).getHashVersion());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidCostFactor1() {
        hasher.hash("secret".toCharArray(), 3);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidCostFactor2() {
        hasher.hash("secret".toCharArray(), 32);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPwTooLong() {
        hasher.hash(new char[257], 4);
    }

    @Test
    public void testPwNotTooLong() {
        hasher.hash(new char[256], 4);
    }
}
