package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.crypto.bkdf.HashData;

public final class TestCaseHashData {

    public final String base64Encoded;
    public final HashData hashData;

    public TestCaseHashData(String base64Encoded, HashData hashData) {
        this.base64Encoded = base64Encoded;
        this.hashData = hashData;
    }
}
