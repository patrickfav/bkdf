package at.favre.lib.crypto.bkdf;

public class TestCase {

    public final char[] password;
    public final String hash;

    public TestCase(char[] password, String hash) {
        this.password = password;
        this.hash = hash;
    }
}
