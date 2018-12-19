package at.favre.lib.crypto.bkdf.util;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.HashData;
import at.favre.lib.crypto.bkdf.Version;

import java.util.Random;

public final class TestCaseHashData {

    public final String base64Encoded;
    public final HashData hashData;

    public TestCaseHashData(String base64Encoded, HashData hashData) {
        this.base64Encoded = base64Encoded;
        this.hashData = hashData;
    }

    static void createRefHashData() {
        Random r = new Random();

        for (int i = 0; i < 100; i++) {
            byte cost = (byte) (r.nextInt(27) + 4);
            Version version = r.nextBoolean() ? Version.HKDF_HMAC512 : Version.HKDF_HMAC512_BCRYPT_24_BYTE;
            String versionName = version == Version.HKDF_HMAC512 ? "Version.HKDF_HMAC512" : "Version.HKDF_HMAC512_BCRYPT_24_BYTE";
            byte[] salt = Bytes.random(16).array();
            byte[] hash = Bytes.random(version.getHashByteLength()).array();
            StringBuilder sb = new StringBuilder();
            sb.append("new TestCaseHashData(");
            sb.append("\"").append(new HashData(
                    cost,
                    version,
                    salt,
                    hash
            ).getAsEncodedMessageFormat()).append("\", ");
            sb.append("new HashData((byte) ").append(cost).append(", ").append(versionName).append(", ");
            sb.append("Bytes.parseHex(\"").append(Bytes.wrap(salt).encodeHex()).append("\").array(), Bytes.parseHex(\"").append(Bytes.wrap(hash).encodeHex()).append("\").array())),");
            System.out.println(sb.toString());
        }
    }
}
