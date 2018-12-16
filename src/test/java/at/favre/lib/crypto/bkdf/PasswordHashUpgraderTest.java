package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class PasswordHashUpgraderTest {

    @Test
    public void testSimpleUpgrade() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        int logRounds = 5;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);

        PasswordHashVerifier verifier = new PasswordHashVerifier.Default();
        assertTrue(verifier.verify(pw, hash));

        PasswordHashUpgrader.Default upgrader = new PasswordHashUpgrader.Default(new SecureRandom());
        PasswordHashUpgrader.CompoundHashData compoundHashData =
                upgrader.upgradePasswordHash(Version.HKDF_HMAC512_BCRYPT_24_BYTE, 7, hash);

        HashData hashData = HashData.parse(hash);
        List<PasswordHashUpgrader.HashConfig> configList = new ArrayList<>(2);
        configList.add(new PasswordHashUpgrader.HashConfig(Version.HKDF_HMAC512, (byte) logRounds));
        configList.add(new PasswordHashUpgrader.HashConfig(Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) 7));

        byte[] upgradedData2 = upgrader.createCompoundHashMessage(configList, hashData.rawSalt, pw);

        assertArrayEquals(compoundHashData.createBlobMessage(), upgradedData2);
        System.out.println(compoundHashData.createBase64Message());
        System.out.println(Bytes.wrap(compoundHashData.createBlobMessage()).encodeHex());
    }

}
