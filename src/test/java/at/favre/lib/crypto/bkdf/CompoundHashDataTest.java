package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.util.TestCaseCompoundHashData;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class CompoundHashDataTest {
    @Test
    public void testEqualsAndHashCode() {
        CompoundHashData c1 = new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), new byte[HashData.SALT_LENGTH_BYTE], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);
        CompoundHashData c2 = new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), new byte[HashData.SALT_LENGTH_BYTE], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);

        assertEquals(c1, c2);
        assertEquals(c1.hashCode(), c2.hashCode());

        CompoundHashData c3 = new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), new byte[HashData.SALT_LENGTH_BYTE], new byte[Version.MAX_BCRYPT_HASH_LENGTH_BYTE]);

        assertNotEquals(c2, c3);
        assertNotEquals(c2.hashCode(), c3.hashCode());

        CompoundHashData c4 = new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 4)), new byte[HashData.SALT_LENGTH_BYTE], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);

        assertNotEquals(c2, c4);
        assertNotEquals(c2.hashCode(), c4.hashCode());
    }

    @Test
    public void testWipe() {
        CompoundHashData d = new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), Bytes.random(HashData.SALT_LENGTH_BYTE).array(), new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);
        byte[] refSalt = Bytes.from(d.rawSalt).array();
        byte[] refHash = Bytes.from(d.rawHash).array();

        assertNotSame(refSalt, d.rawSalt);
        assertNotSame(refHash, d.rawHash);

        d.wipe();

        assertNotEquals(Bytes.wrap(refSalt), Bytes.wrap(d.rawSalt));
        assertNotEquals(Bytes.wrap(refHash), Bytes.wrap(d.rawHash));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalSaltSize1() {
        new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), Bytes.random(17).array(), Bytes.random(Version.MIN_BCRYPT_HASH_LENGTH_BYTE).array());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalSaltSize2() {
        new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), Bytes.random(15).array(), Bytes.random(Version.MIN_BCRYPT_HASH_LENGTH_BYTE).array());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalHashSize1() {
        new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), Bytes.random(HashData.SALT_LENGTH_BYTE).array(), Bytes.random(Version.MIN_BCRYPT_HASH_LENGTH_BYTE - 1).array());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalHashSize2() {
        new CompoundHashData(Collections.singletonList(new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)), Bytes.random(HashData.SALT_LENGTH_BYTE).array(), Bytes.random(Version.MAX_BCRYPT_HASH_LENGTH_BYTE + 1).array());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructEmptyHashConfig() {
        new CompoundHashData(Collections.<CompoundHashData.Config>emptyList(), Bytes.random(HashData.SALT_LENGTH_BYTE).array(), Bytes.random(Version.MIN_BCRYPT_HASH_LENGTH_BYTE).array());
    }

    @Test
    public void testReferenceEncodedHashData() {
        TestCaseCompoundHashData[] testData = new TestCaseCompoundHashData[]{
                new TestCaseCompoundHashData("_gIBBAEE8pj9oU5DfdK9zPZFEWN4jpYnEDyg7LvU6bDce2A5HQkLQyBREuoG",
                        new CompoundHashData(
                                Arrays.asList(
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 4)
                                ),
                                Bytes.parseHex("F298FDA14E437DD2BDCCF6451163788E").array(), Bytes.parseHex("9627103CA0ECBBD4E9B0DC7B60391D090B43205112EA06").array())),
                new TestCaseCompoundHashData("_gIBBQIF4J6wkC9qdupldon4uetLvs3aN02CI2Hkye2yW1VdQLZg6Lk626wdcg==",
                        new CompoundHashData(
                                Arrays.asList(
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 5),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5)
                                ),
                                Bytes.parseHex("E09EB0902F6A76EA657689F8B9EB4BBE").array(), Bytes.parseHex("CDDA374D822361E4C9EDB25B555D40B660E8B93ADBAC1D72").array())),
                new TestCaseCompoundHashData("_gMCBQEMAgngnrCQL2p26mV2ifi560u-zdo3TYIjYeTJ7bJbVV1AtmDouTrbrB1y",
                        new CompoundHashData(
                                Arrays.asList(
                                        new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 5),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 12),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 9)
                                ),
                                Bytes.parseHex("E09EB0902F6A76EA657689F8B9EB4BBE").array(), Bytes.parseHex("CDDA374D822361E4C9EDB25B555D40B660E8B93ADBAC1D72").array())),
                new TestCaseCompoundHashData("_gQBBQEFAQcBBtuX480zQkVY19lRQHkfJxnjMQ9vsgMCs13hs7CSs75lQOe4rNVMIA==",
                        new CompoundHashData(
                                Arrays.asList(
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 5),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 5),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 7),
                                        new CompoundHashData.Config(Version.HKDF_HMAC512, (byte) 6)
                                ),
                                Bytes.parseHex("DB97E3CD33424558D7D95140791F2719").array(), Bytes.parseHex("E3310F6FB20302B35DE1B3B092B3BE6540E7B8ACD54C20").array()))
        };

        for (TestCaseCompoundHashData testDatum : testData) {
            assertEquals(testDatum.base64Encoded, testDatum.hashData.getAsEncodedMessageFormat());
            assertEquals(testDatum.hashData, CompoundHashData.parse(testDatum.base64Encoded));
            assertEquals(testDatum.hashData, CompoundHashData.parse(Bytes.parseBase64(testDatum.base64Encoded).array()));
            assertArrayEquals(testDatum.hashData.getAsBlobMessageFormat(), Bytes.parseBase64(testDatum.base64Encoded).array());
        }
    }
}
