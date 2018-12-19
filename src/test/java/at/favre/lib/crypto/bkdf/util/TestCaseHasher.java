package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.crypto.bkdf.BKDF;
import at.favre.lib.crypto.bkdf.PasswordHasher;
import at.favre.lib.crypto.bkdf.Version;

import java.util.Arrays;
import java.util.List;

public final class TestCaseHasher {

    public final char[] password;
    public final String hash;

    public TestCaseHasher(char[] password, String hash) {
        this.password = password;
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

        System.out.println("\nVERSION 0x01: HKDF_HMAC512 - 23 Byte bcrypt");
        printHashes(passwords, BKDF.createPasswordHasher(Version.HKDF_HMAC512));
        System.out.println("\nVERSION 0x02: HKDF_HMAC512 - 24 Byte bcrypt");
        printHashes(passwords, BKDF.createPasswordHasher(Version.HKDF_HMAC512_BCRYPT_24_BYTE));
    }

    private static void printHashes(List<char[]> passwords, PasswordHasher hasherV1) {
        for (int i = 4; i < 12; i++) {
            for (char[] password : passwords) {
                String msg = hasherV1.hash(password, i);
                System.out.println("new TestCaseHasher (\"" + String.valueOf(password) + "\".toCharArray(),\"" + msg + "\"),");
            }
        }
    }
}
