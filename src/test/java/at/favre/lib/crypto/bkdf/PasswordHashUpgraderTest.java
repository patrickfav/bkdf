package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.util.TestCaseUpgrader;
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
    private PasswordHashVerifier verifier;

    @Before
    public void setup() {
        upgrader = new PasswordHashUpgrader.Default(new SecureRandom());
        hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        verifier = BKDF.createPasswordHashVerifier();
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

    private final TestCaseUpgrader[] testCasesUpgradeCount1 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gICBQEGUoga3E7nC3OzD_IDzC8SqtWhqML1hS2vDjfYLs3-Vjx2yVy1la3q"),
            new TestCaseUpgrader("aa".toCharArray(), "_gICBgIEXhNPJ-aMnEibCb1DF4jFNwWwfhekcn042KsSxSFquljj8ayX0WlcmQ=="),
            new TestCaseUpgrader("aaa".toCharArray(), "_gICBQEGl_qyN0QmZgBOQuXiNJUuUv_3Sm0080k2kHRfpbZdsUugkKBN0ksS"),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gIBBAEEONFeCTNFRTaWmeixx0_Mo8zNmSvBCLQoSUSf_umcGWTmS1042S3_"),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gIBBAIE_bUfgdT8kz8uJfQKguyWXxd_o9jObnWi6cpg4dSLSvABZ7P075qUeQ=="),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gICBQEF0fD8K8k0JPeNbGNMUl0Me2VVTCIgVza5p-mEAJ-3BK98Ut_tadL0"),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gICBgIGbKEYY-0lra5nzdqYo94yVftMm7E7kgyFUVhmWmVdY_tPyh2g8W6rIw=="),
    };

    @Test
    public void testVerifyReferenceTestUpgradeCount1() {
        for (TestCaseUpgrader testCase : testCasesUpgradeCount1) {
            verifier.verify(testCase.password, testCase.hash);
        }
    }

    private final TestCaseUpgrader[] testCasesUpgradeCount2 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gMBBQIFAQZ6xH0X_SusDcQCSCxa69C_wEEQI07LWf7SXNXXubwJ-61n-5oo_-s="),
            new TestCaseUpgrader("aa".toCharArray(), "_gMCBQIEAgRRz-2YbXFDQyAPG95kRwZRTD_UnMctxO8lyIDUdrETTgz_qoMcP42M"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gMCBgEGAQaZcYu2vhJ0lnNUA6gAAkGd-j6xB69LrQH1vaIBqM43OONe4YBq2qU="),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gMBBgIFAgZSQ55dvwwSIWUIjvpIPp-tzmY95juGPxYctyLLxk6gNxRUaTLceuQ1"),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gMCBgIEAgQUUAlXgtF1Wwpfe0jV0uJCvNWexkZWsUt2d1izQDz-lx2ehPmc52sG"),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gMCBgIGAQWdNrQu0CFfzh7U0NoDbiDNq4D6kTke6fj3onNoy66dgT7LUrBdjXc="),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gMCBQEEAgXXNWyCMDzFywabNGC94HjWk_-uYztXSrnTkArV8Wg7sq8rebcwuI99")
    };

    @Test
    public void testVerifyReferenceTestUpgradeCount2() {
        for (TestCaseUpgrader testCase : testCasesUpgradeCount2) {
            verifier.verify(testCase.password, testCase.hash);
        }
    }

    private final TestCaseUpgrader[] testCasesUpgradeCount4 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gUBBQEEAgQCBgEGgCrrUwkGLj9O_xFGMeuXNey6w8rFyOZnjRVxKJv4Bruyji5rsK6V"),
            new TestCaseUpgrader("aa".toCharArray(), "_gUBBQEEAQYBBQEGb_oflUTXNK53qE_TLiqhnRkqhpnQ0pKg3i6oUDF6ufy_3vbvzgnF"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gUBBgEFAQUCBgEG1dHDEQLZUXrz162JQPBEKBDj9FAgvpRUw-ZAq8fOFju2WUFcDhq0"),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gUCBQIEAQYCBQIFAbW4j1ck0ECYEOveSnnrFMGnqfkif8UYSOlx6ZAyKb0PYKL-AskXhw=="),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gUBBgIEAQYBBgEE2eEBwLSKWf1-JdMGuDD65jxi95WHs_bm65a_fADuBlFSVbtgQ_lo"),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gUCBgIGAgUBBAEFz_gn8vxRq07mcsAqFeibpuc9htNJjMEi3_gUKmrYYif_Tv1c9ni4"),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gUBBAEFAQYCBQIG3rCRJaSNzijIQqXavmHiWiOjgfKhfr_1rQ2zLHNfKyx8-LYKUt2cEw==")
    };

    @Test
    public void testVerifyReferenceTestUpgradeCount4() {
        for (TestCaseUpgrader testCase : testCasesUpgradeCount4) {
            verifier.verify(testCase.password, testCase.hash);
        }
    }

    private final TestCaseUpgrader[] testCasesUpgradeCount10 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gsBBAEGAQQCBQEEAQYCBgEEAQQCBQIGypXPPirdTVL5dQzOkoReYhnbDRAldaeTCRzbCaUJhRuYzkxAFV-wdA=="),
            new TestCaseUpgrader("aa".toCharArray(), "_gsBBgIGAQUBBQIFAQYBBAEEAQUBBAEFtlTAimutubnVn2H1Xc4TTVl4vhZSQWNVm7z1RMK6LrXlZtyFT9G-"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gsBBAEGAgQBBgEGAQUBBAIGAQQCBgIGdz8HhBsK6gfMFbNABsFu5K1SGJC6hfOA2S06bJ1djPq1d0fv1XgoUQ=="),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gsCBQEEAgUBBQIFAgQCBQIFAgQCBQEFdMUGhqiHkPw7PGkdZGzZL9FjYJhpMouhR6YV_W2El5MJDCFdhvuI"),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gsCBgIFAgUBBgIGAgYCBQEFAQUBBQEGc3u9eXCxjSuPV2gYgb6sYdWH3Rm-gyTpvs5TQ_sQqTAuhR_6L-_A"),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gsBBgIGAQQCBQEEAQYBBAIGAgQBBgIGDQVuk2F5LOYg68ivD7kOUA0uYcVTo9MdziF6ax8WstKwGLPcLdBveQ=="),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gsCBgEEAQYBBQIGAQYBBQIFAQQBBQIFHZ_tuFTbcYR-1pQkRbTnKHAuzv7BYcGHPttG5bvOvIJpxMxQVnBONw==")
    };

    @Test
    public void testVerifyReferenceTestUpgradeCount10() {
        for (TestCaseUpgrader testCase : testCasesUpgradeCount10) {
            verifier.verify(testCase.password, testCase.hash);
        }
    }
}
