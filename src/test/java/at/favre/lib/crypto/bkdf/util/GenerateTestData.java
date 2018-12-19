package at.favre.lib.crypto.bkdf.util;

import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class GenerateTestData {
    @Test
    public void createHashDataTestData() {
        TestCaseHashData.createRefHashData();
    }

    @Test
    public void createPasswordHashesReferencesHashes() {
        TestCaseHasher.createReferenceHashes();
    }

    @Test
    public void createPasswordUpgraderReferencesHashes() {
        TestCaseUpgrader.createReferenceHashes();
    }
}
