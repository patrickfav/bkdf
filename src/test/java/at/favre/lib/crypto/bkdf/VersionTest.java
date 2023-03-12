package at.favre.lib.crypto.bkdf;

import at.favre.lib.hkdf.HKDF;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class VersionTest {

    @Test
    public void testEquals() {
        assertEquals(Version.HKDF_HMAC512, Version.HKDF_HMAC512);
        assertEquals(new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45));
        assertNotEquals(new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x46), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45));
        assertNotEquals(new Version.Default(HKDF.fromHmacSha512(), 24, (byte) 0x45), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45));
        assertNotEquals(new Version.Default(HKDF.fromHmacSha256(), 23, (byte) 0x45), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45));
    }

    @Test
    public void testHashCode() {
        assertEquals(Version.HKDF_HMAC512.hashCode(), Version.HKDF_HMAC512.hashCode());
        assertEquals(new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45).hashCode(), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45).hashCode());
        assertNotEquals(new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x46).hashCode(), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45).hashCode());
        assertNotEquals(new Version.Default(HKDF.fromHmacSha512(), 24, (byte) 0x45).hashCode(), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45).hashCode());
        assertNotEquals(new Version.Default(HKDF.fromHmacSha256(), 23, (byte) 0x45).hashCode(), new Version.Default(HKDF.fromHmacSha512(), 23, (byte) 0x45).hashCode());
    }

    @Test
    public void testGetHkdf() {
        assertEquals(HKDF.fromHmacSha512(), Version.HKDF_HMAC512.getHkdf());
        assertEquals(HKDF.fromHmacSha512(), Version.HKDF_HMAC512_BCRYPT_24_BYTE.getHkdf());
        assertEquals(HKDF.fromHmacSha256(), new Version.Default(HKDF.fromHmacSha256(), 23, (byte) 0x45).getHkdf());
    }

    @Test
    public void testGetVersionCode() {
        assertEquals(0x01, Version.HKDF_HMAC512.getVersionCode());
        assertEquals(0x02, Version.HKDF_HMAC512_BCRYPT_24_BYTE.getVersionCode());
        assertEquals((byte) 0x45, new Version.Default(HKDF.fromHmacSha256(), 23, (byte) 0x45).getVersionCode());
    }

    @Test
    public void testGetHashByteLength() {
        assertEquals(23, new Version.Default(HKDF.fromHmacSha256(), 23, (byte) 0x45).getHashByteLength());
        assertEquals(24, new Version.Default(HKDF.fromHmacSha256(), 24, (byte) 0x45).getHashByteLength());
        assertEquals(Version.MIN_BCRYPT_HASH_LENGTH_BYTE, Version.HKDF_HMAC512.getHashByteLength());
        assertEquals(Version.MAX_BCRYPT_HASH_LENGTH_BYTE, Version.HKDF_HMAC512_BCRYPT_24_BYTE.getHashByteLength());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalHashLength() {
        new Version.Default(HKDF.fromHmacSha256(), 22, (byte) 0x01);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalHashLength2() {
        new Version.Default(HKDF.fromHmacSha256(), 25, (byte) 0x01);
    }

    @Test(expected = Version.UnsupportedBkdfVersionException.class)
    public void testUnknownVersionCode() {
        Version.Util.getByCode((byte) 0xFF);
    }

    @Test
    public void testUnknownVersionCodeException() {
        try {
            Version.Util.getByCode((byte) 0xFF);
        } catch (Version.UnsupportedBkdfVersionException e) {
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void testKnownVersionCode() {
        assertEquals(Version.HKDF_HMAC512, Version.Util.getByCode((byte) 0x01));
        assertEquals(Version.HKDF_HMAC512_BCRYPT_24_BYTE, Version.Util.getByCode((byte) 0x02));
    }
}
