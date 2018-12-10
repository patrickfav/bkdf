package at.favre.lib.crypto.bkdf;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class PasswordHasherTest {

    private final TestCase[] testCases = new TestCase[]{
            // VERSION 0x01: HKDF_HMAC512 - 23 Byte bcrypt
            new TestCase("a".toCharArray(), "AQSwjQvdDbgRzKhC7ltNYGfYKPTLzQtz5QzmOwLoT6N5Ae2KUDTKN3A="),
            new TestCase("aa".toCharArray(), "AQQ_wDw3SJpGyiU0uAu-EvroF2pLn8g1Xb8YLnvmSYsrBUW9y_g1ZhM="),
            new TestCase("aaa".toCharArray(), "AQTSxw0nKDubdkzhtbfAHu-42uCsl_f7hAXAcWiDYDLUm6a-PdarUSw="),
            new TestCase("Secret1234%$!".toCharArray(), "AQRnvG5jQ3cPnhoPpd69KqWI4MN8khjhemqWQu277zwfQB_BCb_W_w0="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQTA3YPVlMDOTdbirJyRWwSk65vR4uB5SWybFgJkTyetckacArZjuEU="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQTzTkIlV3HqnUJblvY_JzWgl7g9sakcTe87Xphl9-YM0_q0nKl-_oc="),
            new TestCase("ππππππππ".toCharArray(), "AQSoRA_jrchl0Ils_U3DGeekS5Egr_WupsryqmWuyCwOvv0T6hKZIjE="),
            new TestCase("a".toCharArray(), "AQXWj0mmLRdqg3OWc-CSwtwR8krKHeu_Ce9BI9tAVT4274JgHEx-w94="),
            new TestCase("aa".toCharArray(), "AQVPzi-QGCzyJrGyEcZwYGFQ1QErPXa2KV5Pm5lgjN_fuEWs3fkGRD8="),
            new TestCase("aaa".toCharArray(), "AQWc1ka7SxS_N-6Ra3aCI1cKmBL-tU-KG0Q5UAfBO1J4DAB9dhe08TU="),
            new TestCase("Secret1234%$!".toCharArray(), "AQV-5vU4VXRaI5eA_1SGDLWhpK8wcQp3BqjgdJgmpsODQOGOp3UDWzs="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQU3lHA_BUtCLeFQk0Xu2JrW-_E7aT10l75ERBizH1eQ8jwqc22arFU="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQXbBzqPA6nRRs7qU791gXOThdAdA8n16-2NRjCyDy_fKnoCpR4NQp8="),
            new TestCase("ππππππππ".toCharArray(), "AQWfyJ1bzpZ2oFWtbPUSfTfOlHYw6Gr204rC0EY2mVgf5F7N70a00ZI="),
            new TestCase("a".toCharArray(), "AQbXHGI7sxzDK9OmhGVd9TlRV5s_48ot1jhqtcSmwqfD-Gw3sruJYSo="),
            new TestCase("aa".toCharArray(), "AQYOBcLt7ZBzt7ctYXNcN8mrTPuE2olvl_TIt_7N_RJ8__dOsh2lEF8="),
            new TestCase("aaa".toCharArray(), "AQYZcc48U179F7UQ-u3XGBti22PXirpz3Sz7HD7VuRLJCp9VhFfQOTg="),
            new TestCase("Secret1234%$!".toCharArray(), "AQb72fyfpZRO96OXoDzlCUS8nt5ztPftvWWATW06rs9lHp1enzxs6cE="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQbWXqB5H8-1FHOKlQsD8LZIkr7HM7I6pr2qax_mwIfQ5RApwIMP70M="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQbjapqjvaaJcFSH0CaagZXbWAYhSh4jCvVoZLzhxQyCyzyN-eb4_5k="),
            new TestCase("ππππππππ".toCharArray(), "AQZyF5pKbL64K1euvzrtrhj46DTVUF83nMk70pAOs2ZbTbmWSvYK7v4="),
            new TestCase("a".toCharArray(), "AQfcfwP0TSJArSbQR9X0W18FpyrtYMeBOtHVdYYeVtiRaPBQ5Tsr31g="),
            new TestCase("aa".toCharArray(), "AQcaOqD1r8THXB0kS_MNC2rMHtf2a5L6BNB7-Hc-enza2PbwnqTgv1I="),
            new TestCase("aaa".toCharArray(), "AQdNBL_B-HJBbyuY42wpYsFsRkety8e7RdwMwTmhaW6iEZ40rd0DClg="),
            new TestCase("Secret1234%$!".toCharArray(), "AQc59OjyKb93v-FmW7yIdH-KATG52Q2StVzKETw5sL1i8skZJnfQ5NY="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQeNWdwsp8JYCQaXkCazmBJ_CPRsrvMNEJNY-XCb8W_ZaZY9g-ludeA="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQe2NorhjAkFvt1gH_M1SqpwjdMhVDXXaE6kXaRSr_Hxl8kJCp0fw48="),
            new TestCase("ππππππππ".toCharArray(), "AQf-P_mr6vmswWCtPz5t2a21Zljssc3RktmVJ_3qQQicKpyfEksR5GM="),
            new TestCase("a".toCharArray(), "AQhosbm_ECx7e4bvDZhG5BznRzvhrCAz2wZ-HFO8nfAye8Cu9YxM6_4="),
            new TestCase("aa".toCharArray(), "AQgrO26s0C-8EghBa9hvXApf5aZra-jxiE6a0k7LggYKhZgaiD_c_KE="),
            new TestCase("aaa".toCharArray(), "AQhB3Apmo0s1gQZCCOFzio5lZxf67JpYtaMWS9P3o3yrCe9x8Tt6Kq4="),
            new TestCase("Secret1234%$!".toCharArray(), "AQjWJIUIer9BzbV5apbbPoVJ0-aiO-u44ACQgUOlZNDRjL3XwKAf8rM="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQj6akPmJ-m6-MQQNiQ9SJ7pYNSjaT8T6nwYNS1_fcad8Z1FCzs1myo="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQiOoh-c_Qm4JO1vl23gDGPtGWdJOSigFPz9RlrMjrs7TeHGIPhlASw="),
            new TestCase("ππππππππ".toCharArray(), "AQjwMeoROz2fEOc1PXBVNJDF3o_AyHpvNlCLkTtdRPxsQ9ZSsA5TiuA="),
            new TestCase("a".toCharArray(), "AQkwN9DtKjrR-VKa1B1NTItTsrNWsrF3nP2n2AvnZB_8nPX9zIM9ffA="),
            new TestCase("aa".toCharArray(), "AQkZ-r4jcOIO_PVf91NbxrEBmc0OnPhlKljgjnt_SYdqkFoX5yK16RE="),
            new TestCase("aaa".toCharArray(), "AQngITi84J4X4f3NBwj8ku_M9g-gXJjJuW8qw7ehJnr_dBMLTPnKyQM="),
            new TestCase("Secret1234%$!".toCharArray(), "AQlp0a9kL6mXv_jfVjkz2LYXg_X_ORByfgwMSDPqJugSQhOzSLSAZpo="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQnue6mD3valLWUy__Hf_cXJZ-kyEADw4txGGdzIt0wHkAJ-R6Pk970="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQlpTkRDNWlSeLEAy1USqH77v9FNK9KO7GB4WuSY4CGwW64Cv2PPMW4="),
            new TestCase("ππππππππ".toCharArray(), "AQm8W8q0dtGN2aObDgQLilez6aSu0_QpgLwukFK_0mCcYLV6F0sTqXA="),
            new TestCase("a".toCharArray(), "AQobXD5NGKPTxPRQ_5tJohBasKmXrk7VNPunSpkehqMGDUtG8QNE28E="),
            new TestCase("aa".toCharArray(), "AQqIcPqFbdEMrYnn4wjwEFp3opS2mBAx-L9Q2vAucwm2NYkGad3EIQ0="),
            new TestCase("aaa".toCharArray(), "AQqGjmEuR13P47tBgX-59cn3jVgzyl9Ajgqt6LilOrqYAO4wMILeKfw="),
            new TestCase("Secret1234%$!".toCharArray(), "AQqBju3EXAkoVJcfF2DDA1Jk-nXMmD2yyIxbKNULdw7QAHZ1kxJWk0o="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQo6cONAZdvDzc8SITTLyxptmoWPkokh6moX2bJ65SQRxUUzU46MrpY="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQpit1xUHRfK3c4TMDGcpmwD1ntO2clK0zCiylTGuVsAHCIUkpFXRKo="),
            new TestCase("ππππππππ".toCharArray(), "AQpPbFjQsKqFfoIUumZUqJ9Wofx5xg9Iqvp29SA8OllMFuef2GpEuPI="),
            new TestCase("a".toCharArray(), "AQuTkYpHe-46VagB_eHLXzXZMPs4Y75vDvCiUrrHbKls-IQhiC6jvfY="),
            new TestCase("aa".toCharArray(), "AQviBqBKm4g_sLfNoVnoknf2neqXjnCn73Pvqv7uKiSln14_53HYKs8="),
            new TestCase("aaa".toCharArray(), "AQtenp7vFyYbhfuwMLpArYnJX_-L1Xx_iZYHk7WSPm3LwwvtY79YhDE="),
            new TestCase("Secret1234%$!".toCharArray(), "AQtubzCFVmARWa7qAjbcKCgtno29zniN3OHuYgdP7vlhhtQ3797zi5g="),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AQuVKxUgkRZWePa3nuh6uBaPxWBI3IPixl3dyHfFZ9GhktydMQo-pKg="),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AQsVvB0TOZXFU5O_uiLRwbvTCQmF_0RNKdZmou6tFpXdql5NjFnlRC0="),
            new TestCase("ππππππππ".toCharArray(), "AQub1r1BA8YKT76mWj7yKI4f8y8IpyxnyMujG9477t0JKUsNF0W8cSY="),
            // VERSION 0x02: HKDF_HMAC512 - 24 Byte bcrypt
            new TestCase("a".toCharArray(), "AgQZnffizPVD763M7DCru2tQFt8cPmscYjsiyJk77ISz6HROSJwNuU0M"),
            new TestCase("aa".toCharArray(), "AgRR71G91NKq2wqwNZeTy_j4aeZrmaCCaYT81IPOAGRvz_r2ourGUbx8"),
            new TestCase("aaa".toCharArray(), "AgRWGqugSBzEt8cfIuMer2AwdJOQSfAsB30w7tOIAs7NWJkagp0YyHsF"),
            new TestCase("Secret1234%$!".toCharArray(), "AgRfM5Tk1YCQSqgp0ELuPufGWzj1xJonDDhtvvBjgLHDSSydGSV1GGD_"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AgS20JlTAsXaKqVq39cMp7Uzi9n2c3uZKQFVrKWH2EodjDwTr-A5dDoY"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgSt2s-K2NJY_oQAiZb74qtL2QDPZcKDHoPB8rNlWmkxBm9GYNkh4PyQ"),
            new TestCase("ππππππππ".toCharArray(), "AgRp60cis_C4j0M9I1Vf2W4j415Tu9ma-wvdFzMeshfL9Uth_s2Ly1Hn"),
            new TestCase("a".toCharArray(), "AgVtqtCs8T4P9vmcMmm8Z5nZXI4a9j9Ke_nlm1rP4fLtaHA9cKF0xZ4J"),
            new TestCase("aa".toCharArray(), "AgVdQtoxxciohUhPduBqEvwfsfgbQDFyHv3Y7Gbga3OZ-6_aBzMrg99S"),
            new TestCase("aaa".toCharArray(), "AgVWOX8O5zOk2awiuUVxmd1f73nO9Yy0slPaAOVNPBMUXm8hQDH7QdcM"),
            new TestCase("Secret1234%$!".toCharArray(), "AgU07dn7pMfYtQNbvPgtNp0f1f66_-E1KOpdBm_QjzUyAWAkugTh2aub"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AgVc4FYZEtnSqaZxGPQeiAGYy9pATRTvAcf7fwQpSJD7kFyEy2nN8RKk"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgXyMrFQ3bfwnAOG0YCAtd6gdHXEIhbElxUHwqOqpFNiPHswe41V5LnW"),
            new TestCase("ππππππππ".toCharArray(), "AgVgYO3hKsbvhx25lC7PWuBGXwlSFlWUMz9hYOZUNFC9wiHMHHOK1OnK"),
            new TestCase("a".toCharArray(), "AgarrPG5PaglRBdAr0nsM5EUwqDhfKKVJ948xvQxngsFnMGbiO2s4F-V"),
            new TestCase("aa".toCharArray(), "AgZD1PDC7xl7vunQfj1oA4zeTcDHVShdJoHGp7LQ4dUk378CG8BeKayv"),
            new TestCase("aaa".toCharArray(), "Agah1xBjuova1t4pZE6gRVK_F9WhJtmy2V5OMO6FTlbl99y5QjffeukG"),
            new TestCase("Secret1234%$!".toCharArray(), "Aga4ivD1huDGufmc-N03mlFw4MkYp4E0d3qWlCyrQwVCi55PD4CR-kZP"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AgbWHNSLKPfVU3v8uzYd_vp_tAJStGyffMq8O9rarzdcNZpH_0V9nddb"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgaDKkGOeC8cUMfYkSTwshFAHs4ZMFWiJnr7vcdHPGXyJ6XQeAScOpiQ"),
            new TestCase("ππππππππ".toCharArray(), "AgZnqA3v_BGriFIQkJ1s2rnEf5e56A4bBxFWJ7WyCQvTleyWR6Op6yMR"),
            new TestCase("a".toCharArray(), "Agd12YSAjWY890S_gvlXN8NN84UpIbE0xL8KwsycWCd7XT3hQzc9Ff7f"),
            new TestCase("aa".toCharArray(), "Agdm7-vks-T0bvkUW2thkHoChNlq4uPpd8NB1IMJEwHJp1ZUvJeMRvdT"),
            new TestCase("aaa".toCharArray(), "AgeoYb6qUIvv5dhthUOq3_JGDMJbwboFbOXT_CApe06j_LWfarBE4YEQ"),
            new TestCase("Secret1234%$!".toCharArray(), "AgfeRBzs6VK1YR7g_rqTfQ8ayC_uXsJwLjGUZ3Cks46SP9KK3Q-Ti5o3"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AgcCVM_edr88oEvBS_TLbvUxNb3-1R2Qv5DMqFqSSTNV8z68nNJOcjWx"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgdjTpD10bwmmj2wSPdxVDLPUpT_1oUjdZQX4BB-cc8mwV0-PjTe49QS"),
            new TestCase("ππππππππ".toCharArray(), "Age8mn4cr1Z7RXIklscbL2ilqctsx3GjCL59Iso369kJbRkUlEeGHNnQ"),
            new TestCase("a".toCharArray(), "AgiC92oxvvqNGKDl9YzSbHq4Yyidli90mSXpPTx66Y0hdi6_7eGioHuH"),
            new TestCase("aa".toCharArray(), "AghE2QhhscQyKkpjMLDfuHFjXMLK5zjUjw5wn_z2mxfeCK7CKQx-4fod"),
            new TestCase("aaa".toCharArray(), "AgjBmFapcT7lEyeMRJ0mw5Vp0CqQVMCssEImUW8tqO7Hzj-iZm61kcnY"),
            new TestCase("Secret1234%$!".toCharArray(), "AgjmcS7C0igjZtI7bv-R6MlTgwN3UtG3VEe_NSJkU7xzhjUfr9LoimVg"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "Aghe9N4k50_i3RtZ83DD7BdTVQ4HBNDbU-ORo2mt3-cnfHD92jtRr08a"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgiQPFCSmNg-3hRWF_IJzYBPW019S6knMMl7CKYUdhYeGhaQTTrmPaBF"),
            new TestCase("ππππππππ".toCharArray(), "AghVZ6u3cbsx8gksRGw2ha9Z44djRY5C3oUOLyeeDKm_W7lRZz0PCI-l"),
            new TestCase("a".toCharArray(), "AgmjaLts3DYOhV8Ci_vTw25Ndj39zgQxxBAUu5f_XiUfhbvFXlAwMgpD"),
            new TestCase("aa".toCharArray(), "AgkZ1jexkV_HVVUWDf4obZMV7qNeR1Bo6gVCYm7BZkXS90eFxYUp-Jc2"),
            new TestCase("aaa".toCharArray(), "AgldzwW094CrMw_tp9UpnmmRrwtnYc4tLo3L09GQD3qjlsN6AWQeZa_j"),
            new TestCase("Secret1234%$!".toCharArray(), "Agl_KQOg60HgYSYqIvhJEq5aWDFcKopb2_QQhl2U6GFy0HTwBMAAvq9_"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AgknBkTItX9xu0-JXMw7ttt6G8HKXUAfZGUr4vdXSz9jIz3Jjkod3oSY"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "Agl9xZIw5ao0AkVBBYPhMc5VNOQnzRVj9WD0We2ZFH5KJqf4O-0RtCEI"),
            new TestCase("ππππππππ".toCharArray(), "AglQPStgOa6b-zBYpHKnt0i-2cWql1Z6rEaaAgi10ZKS191wxpVYepfU"),
            new TestCase("a".toCharArray(), "AgrJGWBZDZtCBIGVcsDQLN0wrB59RdwdDE1L7eronnrDB-wXso5LJ_7g"),
            new TestCase("aa".toCharArray(), "Agosr2pm3U0zJ5xEducDQgP3ncI69fnsorY17aqs1vX2on0eMUfE2owf"),
            new TestCase("aaa".toCharArray(), "Agp1Ce_KehfP1GH_Bkqot5QgAcBL6oSMRcAj0_CyZ7fjtpGACk3umtAx"),
            new TestCase("Secret1234%$!".toCharArray(), "AgoHqrSk8Ecx81r-LCI7pgClxxjFE-FpMcZFElzLdyrJBdS8kxJAMjB_"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "Agp7Vau1pJA1MO3NuQan5BsSXeStoKtTrvxtGuOKy_l6VwM7QMxazXW8"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "AgrMDhddtVCrrwi0gsSMFOOoQHFpWvmAhVr9lFm1bKvSzGBKR5uM4Mcy"),
            new TestCase("ππππππππ".toCharArray(), "Agr6_bbBBbsN36oG8UZHq-GeOGOFoOEn4KM8qkdkIqSzAMfwxY84O5Ms"),
            new TestCase("a".toCharArray(), "AgtVyjdB4nABcCIsTNgpbDmcYLxIzsu_oMR7nLt5bo6nRvT0R4nih7er"),
            new TestCase("aa".toCharArray(), "AgvC2f3GtTGq4FOYUqPJgsC_GZnujaGrk0ZX7oXyqn6jSGqRCNd5SMev"),
            new TestCase("aaa".toCharArray(), "Agv-Ry2fFtvx44NCaFmXQneCY4SNbi4tWl6EPSuY1WCxIY9okLqkBNwH"),
            new TestCase("Secret1234%$!".toCharArray(), "AgsmPuzGHJDObr81SNgCNuw3qjt5UNJBgKclAL-fOjoSeT2JPtvwjZVk"),
            new TestCase("~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(), "AguWD1nnAzDMCPT5Z6NK9WzQYEUKlobzj47UpVcYLy-7MfIIeyi62zfH"),
            new TestCase("1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(), "Agvr62JkL7nXlSOcHX2GpB8dzIRCRsb_REqj0vHdgB1CKXq4zILAqcq-"),
            new TestCase("ππππππππ".toCharArray(), "AguQbNX7mLO4OvBEgpBrh98LvWF8Gx_GRoRhGunmxlTsjESOSR_Q0n6T")
    };

    @Test
    public void testBasicHasher() {
        PasswordHasher hasher = new PasswordHasher.Default(Version.HKDF_HMAC512, new SecureRandom());
        char[] pw = "secret".toCharArray();
        int logRounds = 6;

        String hash = hasher.hash(pw, logRounds);
        System.out.println(hash);


        PasswordHashVerifier verifier = new PasswordHashVerifier.Default();
        assertTrue(verifier.verify(pw, hash));
    }

    @Test
    public void testVerifyReferenceTest() {
        PasswordHashVerifier verifier = new PasswordHashVerifier.Default();

        for (TestCase testCase : testCases) {
            verifier.verify(testCase.password, testCase.hash);
        }
    }

    //@Test
    public void createReferenceHashes() {

        List<char[]> passwords = Arrays.asList(
                "a".toCharArray(),
                "aa".toCharArray(),
                "aaa".toCharArray(),
                "Secret1234%$!".toCharArray(),
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD".toCharArray(),
                "1jY9EAq1wFINBASejNxISzxXwgGbCrcFJg3/14YHRsd3YCptpkooGUwHCy9FQvei3sCXKE4i48a5hy/".toCharArray(),
                "ππππππππ".toCharArray()
        );

        System.out.println("\nVERSION 0x01: HKDF_HMAC512 - 23 Byte bcrypt");
        printHashes(passwords, BKDF.createPasswordHasher(Version.HKDF_HMAC512));
        System.out.println("\nVERSION 0x02: HKDF_HMAC512 - 24 Byte bcrypt");
        printHashes(passwords, BKDF.createPasswordHasher(Version.HKDF_HMAC512_BCRYPT_24_BYTE));
    }

    private void printHashes(List<char[]> passwords, PasswordHasher hasherV1) {
        for (int i = 4; i < 12; i++) {
            for (char[] password : passwords) {
                String msg = hasherV1.hash(password, i);
                System.out.println("new TestCase (\"" + String.valueOf(password) + "\".toCharArray(),\"" + msg + "\"),");
            }
        }
    }
}
