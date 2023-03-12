package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesValidators;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * A data format encapsulating possible multiple hash configs which were applied to given hash.
 */
@SuppressWarnings("WeakerAccess")
public final class CompoundHashData {

    public final List<Config> configList;
    public final byte[] rawSalt;
    public final byte[] rawHash;

    /**
     * Convert normal hash data to compound format
     *
     * @param hashData to convert
     * @return compound format
     */
    public static CompoundHashData from(HashData hashData) {
        return new CompoundHashData(Collections.singletonList(new Config(hashData.version, hashData.cost)),
                hashData.rawSalt, hashData.rawHash);
    }

    /**
     * Parse given base64 hash message in compound format and returns this data model.
     *
     * @param base64BkdfCompoundHashMsg base64-url encoded msg, see {@link CompoundHashData#getAsEncodedMessageFormat()}
     * @return new instance
     */
    public static CompoundHashData parse(String base64BkdfCompoundHashMsg) {
        return parse(Bytes.parseBase64(base64BkdfCompoundHashMsg).array());
    }

    /**
     * Parse given raw blob hash message in compound format and returns this data model.
     * <p>
     * See {@link CompoundHashData#getAsBlobMessageFormat()}.
     *
     * @param rawHashMessage to parse
     * @return new instance
     * @throws Version.UnsupportedBkdfVersionException if version identifier is not compound type
     */
    public static CompoundHashData parse(byte[] rawHashMessage) {
        ByteBuffer b = ByteBuffer.wrap(rawHashMessage);
        byte version = b.get();

        if (version != PasswordHashUpgrader.COMPOUND_FORMAT_VERSION) {
            throw new Version.UnsupportedBkdfVersionException(version);
        }

        int configCount = Bytes.from(b.get()).toUnsignedByte();

        if (configCount == 0) {
            throw new IllegalArgumentException("there must be at least 1 hash config");
        }

        List<Config> configList = new ArrayList<>(configCount);
        for (int i = 0; i < configCount; i++) {
            Version currentVersion = Version.Util.getByCode(b.get());
            byte costFactor = b.get();
            configList.add(new Config(currentVersion, costFactor));
        }

        byte[] salt = new byte[HashData.SALT_LENGTH_BYTE];
        b.get(salt);

        int hashByteLength = configList.get(configList.size() - 1).version.getHashByteLength();
        byte[] hash = new byte[hashByteLength];
        b.get(hash);

        if (b.remaining() != 0) {
            throw new IllegalArgumentException("unexpected bytes remaining in the message");
        }

        return new CompoundHashData(configList, salt, hash);
    }

    public CompoundHashData(List<Config> configList, byte[] rawSalt, byte[] rawHash) {
        if (Objects.requireNonNull(configList).isEmpty()) {
            throw new IllegalArgumentException("config list must contain at least a single item");
        }

        if (Bytes.wrap(rawSalt).validate(BytesValidators.exactLength(HashData.SALT_LENGTH_BYTE))
                && Bytes.wrap(rawHash).validate(BytesValidators
                .or(BytesValidators.exactLength(Version.MIN_BCRYPT_HASH_LENGTH_BYTE), BytesValidators.exactLength(Version.MIN_BCRYPT_HASH_LENGTH_BYTE + 1)))) {
            this.configList = Collections.unmodifiableList(configList);
            this.rawSalt = Objects.requireNonNull(rawSalt);
            this.rawHash = Objects.requireNonNull(rawHash);
        } else {
            throw new IllegalArgumentException("salt must be exactly " + HashData.SALT_LENGTH_BYTE + " bytes and hash " + Version.MIN_BCRYPT_HASH_LENGTH_BYTE + "/" + (Version.MIN_BCRYPT_HASH_LENGTH_BYTE + 1) + " bytes long");
        }
    }

    /**
     * Wipes salt and hash internally.
     * This instance cannot be used after calling wipe.
     */
    public void wipe() {
        Bytes.wrapNullSafe(this.rawSalt).mutable().secureWipe();
        Bytes.wrapNullSafe(this.rawHash).mutable().secureWipe();
    }

    /**
     * Create the serialized message in raw byte array / blob format.
     * <p>
     * The format is
     * <p>
     * <code>V L CC CC CC CC ... SSSSSSSSSSSSSSSS HHHHHHHHHHHHHHHH</code>
     * <ul>
     * <li>V: the version byte</li>
     * <li>L: unsigned byte of count of hash configs (each 2 byte)</li>
     * <li>CC: 2 byte of bkdf version byte and cost factor</li>
     * <li>S: 16 byte salt</li>
     * <li>H: 23/24 byte hash</li>
     * </ul>
     *
     * @return blob message
     */
    public byte[] getAsBlobMessageFormat() {
        int hashLength = configList.get(configList.size() - 1).version.getHashByteLength();
        ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + (configList.size() * 2) + rawSalt.length + hashLength);
        buffer.put(PasswordHashUpgrader.COMPOUND_FORMAT_VERSION);
        buffer.put((byte) Bytes.from((byte) configList.size()).toUnsignedByte());
        for (Config config : configList) {
            buffer.put(config.version.getVersionCode());
            buffer.put(config.cost);
        }

        buffer.put(rawSalt);
        buffer.put(rawHash);

        return buffer.array();
    }

    /**
     * Similar to {@link CompoundHashData#getAsBlobMessageFormat()} but returns as Base64 url-encoded string
     *
     * @return base64-url encoded string
     */
    public String getAsEncodedMessageFormat() {
        return Bytes.wrap(getAsBlobMessageFormat()).encodeBase64Url();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompoundHashData that = (CompoundHashData) o;
        return Objects.equals(configList, that.configList) &&
                Bytes.wrap(rawSalt).equalsConstantTime(that.rawSalt) &&
                Bytes.wrap(rawHash).equalsConstantTime(that.rawHash);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(configList);
        result = 31 * result + Arrays.hashCode(rawSalt);
        result = 31 * result + Arrays.hashCode(rawHash);
        return result;
    }

    public static final class Config {
        public final Version version;
        public final byte cost;

        public Config(Version version, byte cost) {
            this.version = version;
            this.cost = cost;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Config that = (Config) o;
            return cost == that.cost &&
                    Objects.equals(version, that.version);
        }

        @Override
        public int hashCode() {
            return Objects.hash(version, cost);
        }
    }
}
