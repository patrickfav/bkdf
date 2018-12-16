package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.util.*;

@SuppressWarnings("WeakerAccess")
public final class CompoundHashData {
    public final List<HashConfig> hashConfigList;
    public final byte[] rawSalt;
    public final byte[] rawHash;

    public static CompoundHashData from(HashData hashData) {
        return new CompoundHashData(Collections.singletonList(new HashConfig(hashData.version, hashData.cost)),
                hashData.rawSalt, hashData.rawHash);
    }

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

        List<HashConfig> configList = new ArrayList<>(configCount);
        for (int i = 0; i < configCount; i++) {
            Version currentVersion = Version.Util.getByCode(b.get());
            byte costFactor = b.get();
            configList.add(new HashConfig(currentVersion, costFactor));
        }

        byte[] salt = new byte[16];
        b.get(salt);

        boolean usesOnly23Byte = configList.get(configList.size() - 1)
                .version.isUseOnly23ByteBcryptOut();
        byte[] hash = new byte[usesOnly23Byte ? 23 : 24];
        b.get(hash);

        if (b.remaining() != 0) {
            throw new IllegalArgumentException("unexpected bytes remaining in the message");
        }

        return new CompoundHashData(configList, salt, hash);
    }

    public CompoundHashData(List<HashConfig> hashConfigList, byte[] rawSalt, byte[] rawHash) {
        this.hashConfigList = Collections.unmodifiableList(hashConfigList);
        this.rawSalt = rawSalt;
        this.rawHash = rawHash;
    }

    public void wipe() {
        Bytes.wrapNullSafe(this.rawSalt).mutable().secureWipe();
        Bytes.wrapNullSafe(this.rawHash).mutable().secureWipe();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompoundHashData that = (CompoundHashData) o;
        return Objects.equals(hashConfigList, that.hashConfigList) &&
                Bytes.wrap(rawSalt).equalsConstantTime(that.rawSalt) &&
                Bytes.wrap(rawHash).equalsConstantTime(that.rawHash);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(hashConfigList);
        result = 31 * result + Arrays.hashCode(rawSalt);
        result = 31 * result + Arrays.hashCode(rawHash);
        return result;
    }

    public byte[] createBlobMessage() {
        boolean hashOnly23Byte = hashConfigList.get(hashConfigList.size() - 1).version.isUseOnly23ByteBcryptOut();
        ByteBuffer buffer = ByteBuffer.allocate(1 + 1 + (hashConfigList.size() * 2) + rawSalt.length + (hashOnly23Byte ? 23 : 24));
        buffer.put(PasswordHashUpgrader.COMPOUND_FORMAT_VERSION);
        buffer.put((byte) Bytes.from((byte) hashConfigList.size()).toUnsignedByte());
        for (HashConfig hashConfig : hashConfigList) {
            buffer.put(hashConfig.version.getVersionCode());
            buffer.put(hashConfig.cost);
        }

        buffer.put(rawSalt);
        buffer.put(rawHash);

        return buffer.array();
    }

    public String createBase64Message() {
        return Bytes.wrap(createBlobMessage()).encodeBase64Url();
    }

    public static final class HashConfig {
        public final Version version;
        public final byte cost;

        public HashConfig(Version version, byte cost) {
            this.version = version;
            this.cost = cost;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashConfig that = (HashConfig) o;
            return cost == that.cost &&
                    Objects.equals(version, that.version);
        }

        @Override
        public int hashCode() {
            return Objects.hash(version, cost);
        }
    }
}
