package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.HKDF;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Component responsible for upgrading the strength of BKDF password hashes.
 * <p>
 * Unfortunately it is not easily possible to upgrade the strength of a bcrypt hash WITHOUT the knowledge of the user password. There are
 * usually 2 approaches:
 * <ul>
 * <li>Recompute the hash when the user signs in next time</li>
 * <li>Recompute all hashes offline at once</li>
 * </ul>
 * <p>
 * The disadvantage of the first approach is that the weak hashes remain in the DB until a user logs in again, which may be days, weeks or never.
 * <p>
 * This class introduces an easy way to to support the second approach by providing a defined protocol and data format for hash upgrading by
 * chaining bcrypt hashes.
 * <p>
 * See
 * - https://security.stackexchange.com/questions/15847/is-it-possible-to-increase-the-cost-of-bcrypt-or-pbkdf2-when-its-already-calcula
 * - https://crypto.stackexchange.com/questions/3003/do-i-have-to-recompute-all-hashes-if-i-change-the-work-factor-in-bcrypt
 */
public interface PasswordHashUpgrader {
    /**
     * The current version identifier for the compound hash data format (see {@link CompoundHashData})
     */
    byte COMPOUND_FORMAT_VERSION = (byte) 0xFE;

    /**
     * Upgrades the given hash <strong>with</strong> the given new hash config (ie. version and cost factor).
     * <p>
     * This will chain the current hash with given hash exactly as defined by the the input paramters. E.g.
     * if the current hash is <code>[(VERSION_1, 4)]</code> and the the following will be passed: (VERSION_2, 10), the resulting
     * hash config is <code>[(VERSION_1, 4), (VERSION_2, 10)]</code>.
     *
     * @param version                 of the BKDF password hash to be used
     * @param costFactor              to be used on the current hash
     * @param bkdfPasswordHashFormat2 the current hash. Can be in compound or normal password hash format
     * @return upgraded hash data
     */
    CompoundHashData upgradePasswordHashWith(Version version, int costFactor, String bkdfPasswordHashFormat2);

    /**
     * Upgrades the given hash <strong>with</strong> the given new cost factor and default version
     * <p>
     * This will chain the current hash with given hash exactly as defined by the the input paramters. E.g.
     * if the current hash is <code>[(VERSION_1, 4)]</code> and the the following will be passed: (VERSION_2, 10), the resulting
     * hash config is <code>[(VERSION_1, 4), (VERSION_2, 10)]</code>.
     *
     * @param costFactor              to be used on the current hash
     * @param bkdfPasswordHashFormat2 the current hash. Can be in compound or normal password hash format
     * @return upgraded hash data
     */
    CompoundHashData upgradePasswordHashWith(int costFactor, String bkdfPasswordHashFormat2);

    /**
     * Upgrades the given hash <strong>to</strong> the given new cost factor.
     * <p>
     * This will chain the current hash with possibly multiple hash configs to achieve the new final cost factor. E.g. if current cost-factor
     * is 5 and new cost-factor should be 7, the following sequence of hashes will be applied: <code>5 + [5, 6]</code>. Note that cost-factor
     * is seen as <code>2^cost-factor</code> therefore 5 equals 32 iterations and 7, 128 iterations.
     *
     * @param costFactor              to be the new final cost factor
     * @param bkdfPasswordHashFormat2 the current hash. Can be in compound or normal password hash format
     * @return upgraded hash data
     */
    CompoundHashData upgradePasswordHashTo(int costFactor, String bkdfPasswordHashFormat2);

    /**
     * Verify a hash in compound format.
     * <p>
     * See also {@link CompoundHashData} and {@link PasswordHashVerifier#verify(char[], HashData)}.
     *
     * @param password                to verify against
     * @param bkdfPasswordHashFormat2 containing the hash data
     * @return true iff bcrypt hash in bkdfPasswordHashFormat2 can be computed with given user password
     */
    boolean verifyCompoundHash(char[] password, String bkdfPasswordHashFormat2);

    /**
     * Efficently checks a base64 string if it is in compound hash data format.
     * <p>
     * See {@link #COMPOUND_FORMAT_VERSION} and {@link CompoundHashData}
     *
     * @param bkdfPasswordHashFormat2 to possible be in compound hash format
     * @return iff given data has the version identifier of a compound format
     */
    boolean isCompoundHashMessage(String bkdfPasswordHashFormat2);

    /**
     * Default implementation
     */
    final class Default implements PasswordHashUpgrader {
        private final SecureRandom secureRandom;

        public Default(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
        }

        @Override
        public CompoundHashData upgradePasswordHashWith(Version version, int costFactor, String bkdfPasswordHashFormat2) {
            CompoundHashData compoundHashData = createHashData(bkdfPasswordHashFormat2);

            List<CompoundHashData.Config> newConfigList = new ArrayList<>(compoundHashData.configList);
            newConfigList.add(new CompoundHashData.Config(version, (byte) costFactor));

            PasswordHasher.Default hasher = new PasswordHasher.Default(version, secureRandom);
            byte[] upgradedHash = hasher.hashRaw(compoundHashData.rawHash,
                    deriveSalt(newConfigList.size() - 1, compoundHashData.rawSalt, version.getVersionCode(), (byte) costFactor, compoundHashData.rawHash),
                    costFactor).rawHash;

            return new CompoundHashData(newConfigList, compoundHashData.rawSalt, upgradedHash);
        }

        @Override
        public CompoundHashData upgradePasswordHashWith(int costFactor, String bkdfPasswordHashFormat2) {
            return upgradePasswordHashWith(Version.DEFAULT_VERSION, costFactor, bkdfPasswordHashFormat2);
        }

        /**
         * Derives salt according to password upgrade protocol:
         * <ul>
         * <li>If counter 0: return salt</li>
         * <li>If counter 1+: return hkdf_expand(salt, 4-byte-counter | 1-byte-version_code | 1-byte-cost_factor| prev-bcrypt-hash, 16) with HMAC_SHA512</li>
         * </ul>
         *
         * @param counter     of the current chained hash, e.g. if 4 configs are chained, the counter will go from 0-3
         * @param salt        as found with {@link CompoundHashData#rawSalt}
         * @param versionCode of the currently used password hash, see {@link Version#getVersionCode()}
         * @param costFactor  of the currently used password hash, see {@link CompoundHashData.Config#cost}
         * @return correct derived salt for this round
         */
        private byte[] deriveSalt(int counter, byte[] salt, byte versionCode, byte costFactor, byte[] previousHash) {
            if (counter == 0) {
                return salt;
            } else {
                return HKDF.fromHmacSha512().expand(salt, Bytes.from(counter).append(versionCode).append(costFactor).append(previousHash).array(), 16);
            }
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
            List<Integer> currentCostList = new ArrayList<>(data.configList.size());
            for (CompoundHashData.Config config : data.configList) {
                currentCostList.add((int) config.cost);
            }
            List<Integer> sequence = calcUpgradeSeq(currentCostList, costFactor);
            Version usedVersion = data.configList.get(data.configList.size() - 1).version;

            List<CompoundHashData.Config> newConfigList = new ArrayList<>(data.configList);
            byte[] upgradedHash = data.rawHash;
            PasswordHasher.Default hasher = new PasswordHasher.Default(usedVersion, secureRandom);

            for (Integer seqCf : sequence) {
                newConfigList.add(new CompoundHashData.Config(usedVersion, seqCf.byteValue()));
                upgradedHash = hasher.hashRaw(upgradedHash,
                        deriveSalt(newConfigList.size() - 1, data.rawSalt, usedVersion.getVersionCode(), seqCf.byteValue(), upgradedHash),
                        seqCf).rawHash;
            }

            return new CompoundHashData(newConfigList, data.rawSalt, upgradedHash);
        }

        /**
         * Calculates a possible upgrade path from current hashes to achieve a new target hash. Eg. given the work factor of 5 (=32) and a
         * target of 8 (=256), a path of [5, 6, 7] would be required to achieve 256 iterations.
         *
         * @param fromCostFactor current hash config
         * @param toCostFactor   target strength
         * @return hash configs required to achieve toCostFactor
         */
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

            return sequence;
        }

        @Override
        public boolean verifyCompoundHash(char[] password, String bkdfPasswordHashFormat2) {
            byte[] blobMsg = Bytes.parseBase64(bkdfPasswordHashFormat2).array();
            CompoundHashData data = CompoundHashData.parse(blobMsg);

            CompoundHashData referenceHash = calculateCompoundHash(data.configList, data.rawSalt, password);
            return Bytes.wrap(data.rawHash).equalsConstantTime(referenceHash.rawHash);
        }

        @Override
        public boolean isCompoundHashMessage(String bkdfPasswordHashFormat2) {
            return bkdfPasswordHashFormat2.startsWith(
                    Bytes.from(COMPOUND_FORMAT_VERSION).encodeBase64Url().replaceAll("=", ""));
        }

        private CompoundHashData calculateCompoundHash(List<CompoundHashData.Config> configs, byte[] salt, char[] password) {
            if (configs.size() < 1) {
                throw new IllegalArgumentException("must be at least a single hash config");
            }
            if (configs.size() > 255) {
                throw new IllegalArgumentException("no more than 255 configs allowed");
            }

            byte[] tempHashValue = Bytes.from(password).array();
            int counter = 0;
            for (CompoundHashData.Config config : configs) {
                PasswordHasher.Default hasher = new PasswordHasher.Default(config.version, secureRandom);
                tempHashValue = hasher.hashRaw(tempHashValue,
                        deriveSalt(counter++, salt, config.version.getVersionCode(), config.cost, tempHashValue),
                        config.cost).rawHash;
            }

            return new CompoundHashData(configs, salt, tempHashValue);
        }
    }
}
