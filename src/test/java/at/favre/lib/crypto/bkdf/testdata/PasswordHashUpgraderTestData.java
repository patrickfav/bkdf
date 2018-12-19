package at.favre.lib.crypto.bkdf.testdata;

import at.favre.lib.crypto.bkdf.util.TestCaseUpgrader;

public final class PasswordHashUpgraderTestData {
    private PasswordHashUpgraderTestData() {
    }

    public static final TestCaseUpgrader[] TEST_DATA_UPGRADE_COUNT_01 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gICBgIGMmzXWMB0p6h1cglNl5Dll1gW0Ja4_tJT4UMH2cE9fAP22om81EC6FA=="),
            new TestCaseUpgrader("aa".toCharArray(), "_gICBAEEc0TndxyDo8W-dGfnQOGfCvTwh5SLfV-LVh7IWeeIb8pGoVriG0w3"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gIBBQIFG-R1joJ_nOS14WYawM8fSa-5RugB6X4eCUnnbfOf1HNwCrKwmBqfjg=="),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gICBAIFaYPui6vQQMgMrmjhdZkbropYPQKtLa1HekBK9nQjNh_ECJbd16fRHQ=="),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gIBBQEEqvBzVD7eH2w3C0pn6lLy0_JnCFH6P8onrSBpXlItlgz-9BiHY127"),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gICBgIEJ5tJ9Dqib3OnvecLrnmihtHQcSAUIb0pFyIh4HDtNVQllwBf_CWH9g=="),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gICBQEFfYoSazmNuEVXjlmHeXJMnJIY-lAa7jbBvH3R5ssvDYkEVEUw0ZHv")
    };

    public static final TestCaseUpgrader[] TEST_DATA_UPGRADE_COUNT_02 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gMCBgEGAgTTdwEnbwH4hnM2zuwjbG-u5kuMkZkIcQ9GZTV3935nBlTE0NSGebvD"),
            new TestCaseUpgrader("aa".toCharArray(), "_gMBBgIGAgZQS02c8Li4MDJexcalrejoLZo-J8CznNgpmL96VuV2alMRkEBDOQs6"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gMBBQIFAgYAYb4IqohRz7RS1wy6Cn6UTad-piBBk5DgV7WH-Zk28Aee1uXPZye2"),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gMCBQEGAgYgC-NQR9tIR1J_NWuVjdADtpXrX2vjaFcw7Q0IoL2gUoEoyYu4c32z"),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gMBBQEEAgXXFVvm1H2bXFfF2ZAD8olgREGXAONsW6BM90C4YbX88SDWLUY_UBHP"),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gMCBAEGAgZtY5_u6GhhzyS-l0j3RV6lkW_8Rs9wJjoT_fTaMTMU1fY2kCSaACFA"),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gMCBAEGAgWdRFx6yD8wqOhKUD96JauZ9CgaB8hQzrNENo0RIm17A8utDJw1kVAj")
    };

    public static final TestCaseUpgrader[] TEST_DATA_UPGRADE_COUNT_04 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gUBBQIEAgUCBAIF-efUpaDmuMPhzJLjzL7rX-49f4P7zSvZXtKHVoXTM5F4dHyg8uFbdw=="),
            new TestCaseUpgrader("aa".toCharArray(), "_gUCBQIGAgYCBAEFcdvO8pgHahT30RwDHfse5sBqo0P5YfwP4-kEidMrxD9D2aeh5OYq"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gUBBAEFAgYCBQEFmE509eyho6H4hMSMwVnR3AgN3ejr62VifmGNnIxhKsC4lZM1Vm_W"),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gUBBQEGAgQCBAEFulO8UeiGlcSky55THbcFTPTq_HhspStajs0VCp98N9g7VI2ewh_p"),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gUBBgEGAgYCBQIGrRozL_vsm2mk5JpzSzEbM0tAF5mDY2HzDQt5tloh553378KFfrc9Dw=="),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gUCBgEFAgUBBAIFL4ZQ7--KJY6onkb5FoTWUGHdLreFgg21xk-_UsnKu9x1DrzMFq6-bQ=="),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gUCBAEFAgQCBgEGBOLBIBOxhdT_C_RtHTGwG_SyjpFxfejGEONQLzLAj3aHXo5n-lXV")
    };

    public static final TestCaseUpgrader[] TEST_DATA_UPGRADE_COUNT_10 = new TestCaseUpgrader[]{
            new TestCaseUpgrader("a".toCharArray(), "_gsCBAEGAQUCBQIGAgYCBAEEAgYBBgIElk7nGCjZKZ3zs3kLArWHkKWUzKES_UJZAIvIHKoSARe14VPU6WEIRg=="),
            new TestCaseUpgrader("aa".toCharArray(), "_gsBBgEEAQQBBgIGAgUBBAIFAQQCBAEEYAZ0JMwhQ9nZhcij7wVbLKgM5KE_ilaX9bu6PRR3bpK6kdBWscQQ"),
            new TestCaseUpgrader("aaa".toCharArray(), "_gsBBgEFAQYCBAEGAQYBBQEFAgQBBQIEy0I0hvpeH5uEtv904hwK5JA0Z7Yq8oZKQ6sZCkRYv5RK7TD2G036hQ=="),
            new TestCaseUpgrader("Secret1234%$!".toCharArray(), "_gsCBQIGAgUCBQEGAgUCBQEEAQYBBQIEOJdiMLlXkKcY1KhL9KAusl9syebscAmybnFbQvPLYu-wk8rvmyXoYA=="),
            new TestCaseUpgrader("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "_gsBBQIFAgYBBAIEAQQBBAIFAQQCBgIEA_eAcjrkCGbaKpMZ857SVfqnUOkme_21Sh9jY_IJGFupmsfKlKzOYA=="),
            new TestCaseUpgrader("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "_gsCBQEFAgQCBAIGAQYCBgIEAQUBBAIF9b7DDxReU-cttxYK07EqsvSMzUTLSkHtS2l2joQh7RvqCEhazQtlpQ=="),
            new TestCaseUpgrader("ππππππππ".toCharArray(), "_gsCBgIFAQUCBAIEAgYBBQIFAgUCBgIFcl_UAQEXEz7xh8Oxa7KCitR1fi9r61-5htL7X2aK9qan9Xp7NSrsBw==")
    };
}
