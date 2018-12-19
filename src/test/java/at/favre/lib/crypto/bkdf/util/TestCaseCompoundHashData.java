package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.crypto.bkdf.CompoundHashData;

public final class TestCaseCompoundHashData {

    public final String base64Encoded;
    public final CompoundHashData hashData;

    public TestCaseCompoundHashData(String base64Encoded, CompoundHashData hashData) {
        this.base64Encoded = base64Encoded;
        this.hashData = hashData;
    }
}
