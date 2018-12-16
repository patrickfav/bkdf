package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class PasswordHashUpgraderTest {
    private PasswordHashUpgrader.Default upgrader;

    @Before
    public void setup() {
        upgrader = new PasswordHashUpgrader.Default(new SecureRandom());
    }

    @Test
    public void testSimpleUpgradeBy() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        int logRounds = 5;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));

        CompoundHashData compoundHashData =
                upgrader.upgradePasswordHashBy(Version.HKDF_HMAC512_BCRYPT_24_BYTE, 6, hash);

        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.createBase64Message()));
        System.out.println(Bytes.wrap(compoundHashData.createBlobMessage()).encodeHex(true));
    }

    @Test
    public void testMultiUpgradeBy() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        testMultiUpgrade(hasher, "secret".toCharArray(), 4);
        testMultiUpgrade(hasher, "ππππππππ".toCharArray(), 5);
        testMultiUpgrade(hasher, "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), 5);
    }

    private void testMultiUpgrade(PasswordHasher hasher, char[] pw, int logRounds) {
        String hash = hasher.hash(pw, logRounds);

        CompoundHashData compoundHashData =
                upgrader.upgradePasswordHashBy(Version.HKDF_HMAC512_BCRYPT_24_BYTE, 6, hash);
        compoundHashData = upgrader.upgradePasswordHashBy(Version.HKDF_HMAC512, 5, compoundHashData.createBase64Message());
        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.createBase64Message()));

        compoundHashData = upgrader.upgradePasswordHashBy(Version.HKDF_HMAC512, 4, compoundHashData.createBase64Message());
        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.createBase64Message()));

        System.out.println(compoundHashData.createBase64Message());
        System.out.println(Bytes.wrap(compoundHashData.createBlobMessage()).encodeHex(true));
    }

    @Test
    public void testUpgradePath() {
        testUpgradePath(Collections.singletonList(4), 12, new Integer[]{11, 10, 9, 8, 7, 6, 5, 4});
        testUpgradePath(Collections.singletonList(5), 12, new Integer[]{11, 10, 9, 8, 7, 6, 5});
        testUpgradePath(Collections.singletonList(6), 12, new Integer[]{11, 10, 9, 8, 7, 6});
        testUpgradePath(Collections.singletonList(7), 12, new Integer[]{11, 10, 9, 8, 7});
        testUpgradePath(Collections.singletonList(8), 12, new Integer[]{11, 10, 9, 8});
        testUpgradePath(Collections.singletonList(9), 12, new Integer[]{11, 10, 9});
        testUpgradePath(Collections.singletonList(10), 12, new Integer[]{11, 10});
        testUpgradePath(Collections.singletonList(11), 12, new Integer[]{11});
        testUpgradePath(Collections.singletonList(12), 31, new Integer[]{30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12});

        testUpgradePath(Arrays.asList(4, 8, 5), 12, new Integer[]{11, 10, 9, 7, 6, 4});
        testUpgradePath(Arrays.asList(4, 4, 4, 8, 5, 7), 12, new Integer[]{11, 10, 9, 5, 4});
        testUpgradePath(Arrays.asList(4, 4, 4, 8, 5, 7), 18, new Integer[]{17, 16, 15, 14, 13, 12, 11, 10, 9, 5, 4});
        testUpgradePath(Arrays.asList(4, 4, 4, 5, 6, 6, 6, 6, 6, 9), 13, new Integer[]{12, 11, 10, 6, 5, 4});
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpgradePathIllegalPath1() {
        upgrader.calcUpgradeSeq(Collections.singletonList(12), 12);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpgradePathIllegalPath2() {
        upgrader.calcUpgradeSeq(Collections.singletonList(12), 11);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUpgradePathIllegalPath3() {
        upgrader.calcUpgradeSeq(Arrays.asList(10, 10), 11);
    }

    private void testUpgradePath(List<Integer> fromList, int toCostFactor, Integer[] expected) {
        Object[] arr = upgrader.calcUpgradeSeq(fromList, toCostFactor).toArray();
        System.out.println(Arrays.toString(arr));
        assertArrayEquals(arr, expected);
    }

    @Test
    public void testSimpleUpgradeTo() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        int logRounds = 5;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));

        CompoundHashData compoundHashData = upgrader.upgradePasswordHashTo(6, hash);

        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.createBase64Message()));
        System.out.println(Bytes.wrap(compoundHashData.createBlobMessage()).encodeHex(true));
    }
}
