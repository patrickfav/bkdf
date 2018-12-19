package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

public class PasswordHashUpgraderTest {
    private PasswordHashUpgrader.Default upgrader;
    private PasswordHasher.Default hasher;

    @Before
    public void setup() {
        upgrader = new PasswordHashUpgrader.Default(new SecureRandom());
        hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
    }

    @Test
    public void testSimpleUpgradeBy() {
        char[] pw = "secret".toCharArray();
        int logRounds = 5;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));

        CompoundHashData compoundHashData =
                upgrader.upgradePasswordHashWith(Version.HKDF_HMAC512_BCRYPT_24_BYTE, 6, hash);

        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.getAsEncodedMessageFormat()));
        System.out.println(Bytes.wrap(compoundHashData.getAsBlobMessageFormat()).encodeHex(true));
    }

    @Test
    public void testMultiUpgradeBy() {
        testMultiUpgrade(hasher, "secret".toCharArray(), 4, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4), new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5));
        testMultiUpgrade(hasher, "secret".toCharArray(), 4, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 6), new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 4));
        testMultiUpgrade(hasher, "secret".toCharArray(), 4, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 6), new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4), new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5));
        testMultiUpgrade(hasher, "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), 5, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4), new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5));
    }

    private void testMultiUpgrade(PasswordHasher hasher, char[] pw, int logRounds, CompoundHashData.Config... configs) {
        String hash = hasher.hash(pw, logRounds);

        int counter = 2;
        for (CompoundHashData.Config config : configs) {
            CompoundHashData compoundHashData = upgrader.upgradePasswordHashWith(config.version, config.cost, hash);
            hash = compoundHashData.getAsEncodedMessageFormat();

            assertTrue(upgrader.verifyCompoundHash(pw, hash));
            verifyBase64Msg(hash, config.version, config.cost);
            assertEquals(counter++, compoundHashData.configList.size());
            System.out.println(compoundHashData.getAsEncodedMessageFormat());
            System.out.println(Bytes.wrap(compoundHashData.getAsBlobMessageFormat()).encodeHex(true));
        }
    }

    private void verifyBase64Msg(String compoundMsg, Version refVersion, int refCost) {
        CompoundHashData compoundHashDataRef = CompoundHashData.parse(compoundMsg);
        assertEquals(refVersion, compoundHashDataRef.configList.get(compoundHashDataRef.configList.size() - 1).version);
        assertEquals(refCost, compoundHashDataRef.configList.get(compoundHashDataRef.configList.size() - 1).cost);
    }

    @Test
    public void testMultiUpgradeByUnicode() {
        testMultiUpgrade(hasher, "ππππππππ".toCharArray(), 5, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4), new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5));
        testMultiUpgrade(new PasswordHasher.Default(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom()), "ππππππππ".toCharArray(), 5, new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4), new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 5));
    }

    @Test
    public void testMultiUpgradeByManyUpgrades() {
        Random r = new Random();
        int length = r.nextInt(16) + 8;
        CompoundHashData.Config[] arr = new CompoundHashData.Config[length];

        for (int i = 0; i < arr.length; i++) {
            arr[i] = new CompoundHashData.Config(
                    r.nextBoolean() ? Version.HKDF_HMAC512_BCRYPT_24_BYTE : Version.HKDF_HMAC512,
                    (byte) (r.nextInt(3) + 4)
            );
        }

        testMultiUpgrade(hasher, "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), 5, arr);
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
        char[] pw = "secret".toCharArray();
        int logRounds = 5;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));

        CompoundHashData compoundHashData = upgrader.upgradePasswordHashTo(6, hash);

        assertTrue(upgrader.verifyCompoundHash(pw, compoundHashData.getAsEncodedMessageFormat()));
        System.out.println(Bytes.wrap(compoundHashData.getAsBlobMessageFormat()).encodeHex(true));
    }

    @Test
    public void testMultipleUpgradeTo() {
        testMultiUpgradeTo(hasher, "secret".toCharArray(), 5, 6, 8);
        testMultiUpgradeTo(hasher, "secret".toCharArray(), 4, 9);
        testMultiUpgradeTo(hasher, "secret".toCharArray(), 6, 7);
        testMultiUpgradeTo(hasher, "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), 4, 6);
    }

    private void testMultiUpgradeTo(PasswordHasher hasher, char[] pw, int logRounds, int... upgradeToArr) {
        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        assertTrue(verifier.verify(pw, hash));

        for (int cf : upgradeToArr) {
            CompoundHashData compoundHashData = upgrader.upgradePasswordHashTo(cf, hash);
            assertTrue(verifier.verify(pw, compoundHashData.getAsEncodedMessageFormat()));
            System.out.println(Bytes.wrap(compoundHashData.getAsBlobMessageFormat()).encodeHex(true));
            hash = compoundHashData.getAsEncodedMessageFormat();

            CompoundHashData compoundHashDataRef = CompoundHashData.parse(hash);
            assertEquals(hasher.getHashVersion(), compoundHashDataRef.configList.get(compoundHashDataRef.configList.size() - 1).version);
        }
    }

    @Test
    public void testMultipleUpgradeToUnicode() {
        testMultiUpgradeTo(hasher, "ππππππππ".toCharArray(), 4, 6);
        testMultiUpgradeTo(new PasswordHasher.Default(Version.HKDF_HMAC512_BCRYPT_24_BYTE, new SecureRandom()), "ππππππππ".toCharArray(), 4, 6);
    }

    @Test
    public void testVerifyWithTooManyConfigs() {
        List<CompoundHashData.Config> configs = new ArrayList<>();
        for (int i = 0; i < 255; i++) {
            configs.add(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4));
        }

        assertFalse(upgrader.verifyCompoundHash("secret".toCharArray(), new CompoundHashData(configs, new byte[16], new byte[23]).getAsEncodedMessageFormat()));

        //add 255th element
        configs.add(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4));

        try {
            upgrader.verifyCompoundHash("secret".toCharArray(), new CompoundHashData(configs, new byte[16], new byte[23]).getAsEncodedMessageFormat());
            fail();
        } catch (IllegalArgumentException ignored) {
        }
    }
}
