package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.crypto.bkdf.BKDF;
import at.favre.lib.crypto.bkdf.CompoundHashData;
import at.favre.lib.crypto.bkdf.PasswordHashUpgrader;
import at.favre.lib.crypto.bkdf.PasswordHasher;
import at.favre.lib.crypto.bkdf.Version;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public final class TestCaseUpgrader {

    public final char[] password;
    public final String hash;

    public TestCaseUpgrader(char[] password, String hash) {
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

        System.out.println("\n## 1 Upgrade");
        printHashes(passwords, 1);
        System.out.println("\n## 2 Upgrades");
        printHashes(passwords, 2);
        System.out.println("\n## 4 Upgrades");
        printHashes(passwords, 4);
        System.out.println("\n## 10 Upgrades");
        printHashes(passwords, 10);
    }

    private static void printHashes(List<char[]> passwords, int configsCount) {
        PasswordHashUpgrader upgrader = BKDF.createPasswordHashUpgrader();
        Random r = new Random();

        for (char[] password : passwords) {
            List<CompoundHashData.Config> configs = new ArrayList<>();
            for (int j = 0; j < configsCount; j++) {
                configs.add(new CompoundHashData.Config(r.nextBoolean() ? Version.HKDF_HMAC512 : Version.HKDF_HMAC512_BCRYPT_24_BYTE, (byte) (r.nextInt(3) + 4)));
            }

            PasswordHasher hasher = BKDF.createPasswordHasher(r.nextBoolean() ? Version.HKDF_HMAC512 : Version.HKDF_HMAC512_BCRYPT_24_BYTE);
            String hash = hasher.hash(password, (byte) (r.nextInt(3) + 4));

            for (CompoundHashData.Config config : configs) {
                hash = upgrader.upgradePasswordHashWith(config.version, config.cost, hash).getAsEncodedMessageFormat();
            }

            System.out.println("new TestCaseUpgrader (\"" + String.valueOf(password) + "\".toCharArray(),\"" + hash + "\"),");
        }
    }
}
