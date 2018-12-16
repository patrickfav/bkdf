package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public interface PasswordHashUpgrader {
    byte COMPOUND_FORMAT_VERSION = (byte) 0xFE;

    CompoundHashData upgradePasswordHashBy(Version version, int costFactor, String bkdfPasswordHashFormat2);

    CompoundHashData upgradePasswordHashTo(int costFactor, String bkdfPasswordHashFormat2);

    boolean verifyCompoundHash(char[] password, String bkdfPasswordHashFormat2);

    boolean isCompoundHashMessage(String bkdfPasswordHashFormat2);

    final class Default implements PasswordHashUpgrader {
        private final SecureRandom secureRandom;

        public Default(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
        }

        @Override
        public CompoundHashData upgradePasswordHashBy(Version version, int costFactor, String bkdfPasswordHashFormat2) {
            CompoundHashData compoundHashData = createHashData(bkdfPasswordHashFormat2);

            List<CompoundHashData.HashConfig> newConfigList = new ArrayList<>(compoundHashData.hashConfigList);
            newConfigList.add(new CompoundHashData.HashConfig(version, (byte) costFactor));

            PasswordHasher.Default hasher = new PasswordHasher.Default(version, secureRandom);
            byte[] upgradedHash = hasher.hashRaw(compoundHashData.rawHash, compoundHashData.rawSalt, costFactor).rawHash;

            return new CompoundHashData(newConfigList, compoundHashData.rawSalt, upgradedHash);
        }

        private CompoundHashData createHashData(String bkdfPasswordHashFormat2) {
            byte[] blobMsg = Bytes.parseBase64(bkdfPasswordHashFormat2).array();

            CompoundHashData compoundHashData;
            if (blobMsg[0] == COMPOUND_FORMAT_VERSION) {
                compoundHashData = CompoundHashData.parse(blobMsg);
            } else {
                compoundHashData = CompoundHashData.from(HashData.parse(blobMsg));
            }
            return compoundHashData;
        }

        @Override
        public CompoundHashData upgradePasswordHashTo(int costFactor, String bkdfPasswordHashFormat2) {
            CompoundHashData data = createHashData(bkdfPasswordHashFormat2);
            List<Integer> currentCostList = new ArrayList<>(data.hashConfigList.size());
            for (CompoundHashData.HashConfig config : data.hashConfigList) {
                currentCostList.add((int) config.cost);
            }
            List<Integer> sequence = calcUpgradeSeq(currentCostList, costFactor);
            Version usedVersion = data.hashConfigList.get(data.hashConfigList.size() - 1).version;

            List<CompoundHashData.HashConfig> newConfigList = new ArrayList<>(data.hashConfigList);
            byte[] upgradedHash = data.rawHash;
            PasswordHasher.Default hasher = new PasswordHasher.Default(usedVersion, secureRandom);

            for (Integer seqCf : sequence) {
                upgradedHash = hasher.hashRaw(upgradedHash, data.rawSalt, seqCf).rawHash;
                newConfigList.add(new CompoundHashData.HashConfig(usedVersion, seqCf.byteValue()));
            }

            return new CompoundHashData(newConfigList, data.rawSalt, upgradedHash);
        }

        List<Integer> calcUpgradeSeq(List<Integer> fromCostFactor, int toCostFactor) {
            List<Integer> sequence = new ArrayList<>();
            long currentIterations = 0;
            for (Integer c : fromCostFactor) {
                currentIterations += (long) Math.pow(2, c);
            }
            long targetIterations = (long) Math.pow(2, toCostFactor);

            if (currentIterations >= targetIterations) {
                throw new IllegalArgumentException("target cost factor must be greater than source cost factor");
            }

            for (int i = 31; i >= 4; i--) {
                long iterations = (long) Math.pow(2, i);
                if (currentIterations + iterations <= targetIterations) {
                    sequence.add(i);
                    currentIterations += iterations;
                    i++;
                }
            }

            // System.out.println("target is " + targetIterations + " - current: " + currentIterations);

            return sequence;
        }

        @Override
        public boolean verifyCompoundHash(char[] password, String bkdfPasswordHashFormat2) {
            byte[] blobMsg = Bytes.parseBase64(bkdfPasswordHashFormat2).array();
            CompoundHashData data = CompoundHashData.parse(blobMsg);

            CompoundHashData referenceHash = calculateCompoundHash(data.hashConfigList, data.rawSalt, password);
            return Bytes.wrap(data.rawHash).equalsConstantTime(referenceHash.rawHash);
        }

        @Override
        public boolean isCompoundHashMessage(String bkdfPasswordHashFormat2) {
            return bkdfPasswordHashFormat2.startsWith(
                    Bytes.from(COMPOUND_FORMAT_VERSION).encodeBase64Url().replaceAll("=", ""));
        }

        private CompoundHashData calculateCompoundHash(List<CompoundHashData.HashConfig> hashConfigs, byte[] salt, char[] password) {
            if (hashConfigs.size() < 1) {
                throw new IllegalArgumentException("must be at least a single hash config");
            }
            if (hashConfigs.size() > 255) {
                throw new IllegalArgumentException("no more than 255 configs allowed");
            }

            byte[] tempHashValue = Bytes.from(password).array();
            for (CompoundHashData.HashConfig hashConfig : hashConfigs) {
                PasswordHasher.Default hasher = new PasswordHasher.Default(hashConfig.version, secureRandom);
                tempHashValue = hasher.hashRaw(tempHashValue, salt, hashConfig.cost).rawHash;
            }

            return new CompoundHashData(hashConfigs, salt, tempHashValue);
        }
    }
}
