package at.favre.lib.crypto.bkdf.util;

public final class TestCaseHash {

    public final char[] password;
    public final String hash;

    public TestCaseHash(char[] password, String hash) {
        this.password = password;
        this.hash = hash;
    }
}
