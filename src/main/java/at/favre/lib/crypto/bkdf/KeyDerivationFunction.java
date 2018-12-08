package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;

public interface KeyDerivationFunction {

    byte[] derive(byte[] salt, char[] password, int logRounds, byte[] infoParam, int outLengthByte);

    byte[] derive(byte[] salt, byte[] ikm, int logRounds, byte[] infoParam, int outLengthByte);

    class Default implements KeyDerivationFunction {
        private final HKDF hkdf;
        private final boolean useOnly23ByteBcryptOut;

        public Default(HKDF hkdf, boolean useOnly23ByteBcryptOut) {
            this.hkdf = hkdf;
            this.useOnly23ByteBcryptOut = useOnly23ByteBcryptOut;
        }

        @Override
        public byte[] derive(byte[] salt, char[] password, int logRounds, byte[] infoParam, int outLengthByte) {
            return derive(salt, Bytes.from(password, StandardCharsets.UTF_8).array(), logRounds, infoParam, outLengthByte);
        }

        @Override
        public byte[] derive(byte[] salt, byte[] ikm, int logRounds, byte[] infoParam, int outLengthByte) {
            byte[] extractedPw = hkdf.extract(null, ikm);

            BCrypt.HashData data = BCrypt.with(
                    new BCrypt.Version(new byte[]{0x02, 0x00}, useOnly23ByteBcryptOut, true, null, null))
                    .hashRaw(logRounds, salt, extractedPw);

            return hkdf.expand(data.rawHash, Bytes.from("bkdf").append(infoParam).array(), outLengthByte);
        }
    }
}
