package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class QuickstartTest {

    @Test
    public void quickstart() {
        PasswordHasher hasher = BKDF.createPasswordHasher();

        char[] pw = "secret".toCharArray();
        int costFactor = 6; // same as with bcrypt 4-31 doubling the iterations every increase

        //returns base64 url-safe encoded string
        String hash = hasher.hash(pw, costFactor);

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        boolean verified = verifier.verify(pw, hash);

        assertTrue(verified);
    }

    @Test
    public void passwordHashFull() {
        // provide different version of hash config and provide own impl of secure random for salt gen
        PasswordHasher hasher = BKDF.createPasswordHasher(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        HashData hashData = hasher.hashRaw("secret".toCharArray(), 4);

        // get the raw, non-encoded hash message
        byte[] hashMsgAsBlob = hashData.getAsBlobMessageFormat();

        // get the base64 url-safe encoded string
        String hashAsBase64 = hashData.getAsEncodedMessageFormat();

        PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
        boolean verified = verifier.verify(pw, hashData);

        assertTrue(verified);
    }

    @Test
    public void upgradeHashFull() {
        char[] pw = "secret".toCharArray();

        // hash with cost factor 5
        String hash = BKDF.createPasswordHasher().hash(pw, 5);
        PasswordHashUpgrader upgrader = new PasswordHashUpgrader.Default(new SecureRandom());

        // upgrade hash with an additional cost factor (ie. now needs to calculate 5 + 6 = 32 + 64 = 96 iterations
        CompoundHashData compoundHashData =
                upgrader.upgradePasswordHashWith(Version.HKDF_HMAC512_BCRYPT_24_BYTE, 6, hash);

        // create base64 url-safe encoded msg and verify
        boolean verified = BKDF.createPasswordHashVerifier().verify(pw, compoundHashData.getAsEncodedMessageFormat());
        assertTrue(verified);
    }

    @Test
    public void upgradeHashFull2() {
        char[] pw = "secret".toCharArray();

        // hash with cost factor 5
        String hash = BKDF.createPasswordHasher().hash(pw, 5);
        PasswordHashUpgrader upgrader = new PasswordHashUpgrader.Default(new SecureRandom());

        // upgrade to have exactly cost factor 8 (aka 2^8 = 256 iterations)
        CompoundHashData compoundHashData = upgrader.upgradePasswordHashTo(8, hash);

        // create base64 url-safe encoded msg and verify
        boolean verified = BKDF.createPasswordHashVerifier().verify(pw, compoundHashData.getAsEncodedMessageFormat());
        assertTrue(verified);
    }

    @Test
    public void kdfExample1() {
        char[] pw = "secret".toCharArray();
        byte[] salt = Bytes.random(16).array();
        int costFactor = 5;

        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);
        byte[] aesKey = kdf.derive(salt, pw, costFactor, Bytes.from("aes-key").array(), 16);
        SecretKey aesSecretKey = new SecretKeySpec(aesKey, "AES");

        assertNotNull(aesSecretKey);
    }

    @Test
    public void kdfExample2() {
        // a entropy source used in your current protocol
        byte[] ikm = Bytes.random(12).array();
        byte[] salt = Bytes.random(16).array();
        int costFactor = 5;

        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);
        List<KeyDerivationFunction.KdfConfig> config = Arrays.asList(
                new KeyDerivationFunction.KdfConfig(Bytes.from("aes-key").array(), 16),
                new KeyDerivationFunction.KdfConfig(Bytes.from("mac-key").array(), 32)
        );
        List<byte[]> keys = kdf.deriveMulti(salt, ikm, costFactor, config);

        SecretKey aesSecretKey = new SecretKeySpec(keys.get(0), "AES");
        SecretKey macSecretKey = new SecretKeySpec(keys.get(1), "HmacSHA512");

        assertNotNull(aesSecretKey);
        assertNotNull(macSecretKey);
    }
}
