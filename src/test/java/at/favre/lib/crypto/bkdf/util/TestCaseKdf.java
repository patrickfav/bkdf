package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.BKDF;
import at.favre.lib.crypto.bkdf.KeyDerivationFunction;
import at.favre.lib.crypto.bkdf.Version;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

public final class TestCaseKdf {

    public final char[] password;
    public final byte[] salt;
    public final byte[] info;
    public final int outLength;
    public final int cost;
    public final byte[] hash;

    public TestCaseKdf(char[] password, byte[] salt, byte[] info, int outLength, int cost, byte[] hash) {
        this.password = password;
        this.salt = salt;
        this.info = info;
        this.outLength = outLength;
        this.cost = cost;
        this.hash = hash;
    }

    static void createReferenceHashes() {
        List<char[]> passwords = Arrays.asList(
                "a".toCharArray(),
                "aa".toCharArray(),
                "aaa".toCharArray(),
                "Secret1234%$!".toCharArray(),
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(),
                "1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(),
                "ππππππππ".toCharArray()
        );

        System.out.println("\nVERSION 0x01: 72 byte out");
        printHashes(passwords, BKDF.createKdf(Version.HKDF_HMAC512), 72);
        System.out.println("\nVERSION 0x02: 72 byte out");
        printHashes(passwords, BKDF.createKdf(Version.HKDF_HMAC512_BCRYPT_24_BYTE), 72);
        System.out.println("\nVERSION 0x01: 16 byte out");
        printHashes(passwords, BKDF.createKdf(Version.HKDF_HMAC512), 16);
    }

    private static void printHashes(List<char[]> passwords, KeyDerivationFunction kdf, int outLength) {
        Random r = new Random();
        for (int cost = 4; cost < 12; cost++) {
            for (char[] password : passwords) {
                byte[] salt = Bytes.random(16).array();
                byte[] info = Bytes.random(r.nextInt(32)).array();
                byte[] okm = kdf.derive(salt, password, cost, info, outLength);
                System.out.println("new TestCaseKdf (\"" + String.valueOf(password) + "\".toCharArray(), " +
                        "Bytes.parseHex(\"" + Bytes.wrap(salt).encodeHex() + "\").array()," +
                        "Bytes.parseHex(\"" + Bytes.wrap(info).encodeHex() + "\").array()," +
                        +outLength + ", " +
                        +cost + ", " +
                        "Bytes.parseHex(\"" + Bytes.wrap(okm).encodeHex() + "\").array()),");
            }
        }
    }
}
