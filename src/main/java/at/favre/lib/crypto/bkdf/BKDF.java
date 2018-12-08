package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

import java.security.SecureRandom;

public final class BKDF {

    private BKDF() {
    }

    public static PasswordHasher createPasswordHasher() {
        return new PasswordHasher.Default((byte) Bytes.from((byte) 64).toUnsignedByte(), HKDF.fromHmacSha256(), new SecureRandom(), false);
    }

    public static KeyDerivationFunction createKdf() {
        return new KeyDerivationFunction.Default(HKDF.fromHmacSha256(), false);
    }
}
