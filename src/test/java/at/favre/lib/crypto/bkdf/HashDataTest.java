package at.favre.lib.crypto.bkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bkdf.util.TestCaseHashData;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.*;

public class HashDataTest {
    @Test
    public void testEquals() {
        assertEquals(new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]), new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]));
        assertEquals(new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]));
        assertNotEquals(new HashData((byte) 6, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]));
        assertNotEquals(new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MAX_BCRYPT_HASH_LENGTH_BYTE]));
    }

    @Test
    public void testHashCode() {
        assertEquals(new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode(), new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode());
        assertEquals(new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode(), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode());
        assertNotEquals(new HashData((byte) 6, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode(), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode());
        assertNotEquals(new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]).hashCode(), new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, new byte[16], new byte[Version.MAX_BCRYPT_HASH_LENGTH_BYTE]).hashCode());
    }

    @Test
    public void testWipe() {
        HashData d = new HashData((byte) 4, Version.HKDF_HMAC512, Bytes.random(16).array(), Bytes.random(23).array());
        byte[] refSalt = Bytes.from(d.rawSalt).array();
        byte[] refHash = Bytes.from(d.rawHash).array();

        assertNotSame(refSalt, d.rawSalt);
        assertNotSame(refHash, d.rawHash);

        d.wipe();

        assertNotEquals(Bytes.wrap(refSalt), Bytes.wrap(d.rawSalt));
        assertNotEquals(Bytes.wrap(refHash), Bytes.wrap(d.rawHash));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalSaltSize1() {
        new HashData((byte) 4, Version.HKDF_HMAC512, new byte[17], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalSaltSize2() {
        new HashData((byte) 4, Version.HKDF_HMAC512, new byte[15], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalHashSize1() {
        new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MIN_BCRYPT_HASH_LENGTH_BYTE - 1]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorIllegalHashSize2() {
        new HashData((byte) 4, Version.HKDF_HMAC512, new byte[16], new byte[Version.MAX_BCRYPT_HASH_LENGTH_BYTE + 1]);
    }

    @Test
    public void testReferenceEncodedHashData() {
        TestCaseHashData[] testData = new TestCaseHashData[]{
                new TestCaseHashData("AhQozksLHfNB_lzKdEHo-rqmu0stfEkyRS7aJUG4ONiKtDfJPz1zIBR6", new HashData((byte) 20, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("28ce4b0b1df341fe5cca7441e8fabaa6").array(), Bytes.parseHex("bb4b2d7c4932452eda2541b838d88ab437c93f3d7320147a").array())),
                new TestCaseHashData("AhQl4r8ocH3tw7v01d0-mlvvjmxQFe4Y0aCPGLyRxUCfZMJ-4QrTaILa", new HashData((byte) 20, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("25e2bf28707dedc3bbf4d5dd3e9a5bef").array(), Bytes.parseHex("8e6c5015ee18d1a08f18bc91c5409f64c27ee10ad36882da").array())),
                new TestCaseHashData("AhB7p0PTc8yVGg3POk56qxVU8vr82OthQRl3Wm4pShmAW5oqrrRe9O3q", new HashData((byte) 16, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("7ba743d373cc951a0dcf3a4e7aab1554").array(), Bytes.parseHex("f2fafcd8eb614119775a6e294a19805b9a2aaeb45ef4edea").array())),
                new TestCaseHashData("ARejlKok59N9Mdz-aM39-g6iKqzcksdNx8P5595Mv8nrQJsdqNPvMLE=", new HashData((byte) 23, Version.HKDF_HMAC512, Bytes.parseHex("a394aa24e7d37d31dcfe68cdfdfa0ea2").array(), Bytes.parseHex("2aacdc92c74dc7c3f9e7de4cbfc9eb409b1da8d3ef30b1").array())),
                new TestCaseHashData("AQlwLCptg5gk-phkEQniPwzEe5YZOPK6BNaQN1uLESUzDc3nptuO9DA=", new HashData((byte) 9, Version.HKDF_HMAC512, Bytes.parseHex("702c2a6d839824fa98641109e23f0cc4").array(), Bytes.parseHex("7b961938f2ba04d690375b8b1125330dcde7a6db8ef430").array())),
                new TestCaseHashData("AQk1hJqHpjysk0cVpB3orQNe3Ul90-WN6vnZOZ97jcAJ7WF6fmY0qDc=", new HashData((byte) 9, Version.HKDF_HMAC512, Bytes.parseHex("35849a87a63cac934715a41de8ad035e").array(), Bytes.parseHex("dd497dd3e58deaf9d9399f7b8dc009ed617a7e6634a837").array())),
                new TestCaseHashData("ARu10QhWspOmgZAFYZygc-wP9mnHYMvddwjnr2MRlbI2R8a0wmx8BP0=", new HashData((byte) 27, Version.HKDF_HMAC512, Bytes.parseHex("b5d10856b293a6819005619ca073ec0f").array(), Bytes.parseHex("f669c760cbdd7708e7af631195b23647c6b4c26c7c04fd").array())),
                new TestCaseHashData("AhTHrH2m-zywl_IuwmRWv6LCKqdXK1X870zwXqj0-rJ24jTKoEanPkJb", new HashData((byte) 20, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("c7ac7da6fb3cb097f22ec26456bfa2c2").array(), Bytes.parseHex("2aa7572b55fcef4cf05ea8f4fab276e234caa046a73e425b").array())),
                new TestCaseHashData("Aha_5jzDXZ82IUUGhr3hP7fkggPwftTLmZ_PvHgg1zGcltxW5b_mkQvF", new HashData((byte) 22, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("bfe63cc35d9f3621450686bde13fb7e4").array(), Bytes.parseHex("8203f07ed4cb999fcfbc7820d7319c96dc56e5bfe6910bc5").array())),
                new TestCaseHashData("AghHTUOZVDTQjarIlHRBvCQbUFzmjOCQC3TscJhBwbOt-NECPQZhonfk", new HashData((byte) 8, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("474d43995434d08daac8947441bc241b").array(), Bytes.parseHex("505ce68ce0900b74ec709841c1b3adf8d1023d0661a277e4").array())),
                new TestCaseHashData("AhiN4mGrdP_U_fUQ9Gl3YjiTM0RIFcy7lIkJF3y0U5Z3ePPHdJ1a4959", new HashData((byte) 24, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("8de261ab74ffd4fdf510f46977623893").array(), Bytes.parseHex("33444815ccbb948909177cb453967778f3c7749d5ae3de7d").array())),
                new TestCaseHashData("Ah02Kmxh-daAE73cQowAuAUEV9Acw9me5dMK3jNSN8ggLn_fHgVc2ruH", new HashData((byte) 29, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("362a6c61f9d68013bddc428c00b80504").array(), Bytes.parseHex("57d01cc3d99ee5d30ade335237c8202e7fdf1e055cdabb87").array())),
                new TestCaseHashData("AhHy6ms2x9QVrM3cJdIYSgwqXIIxa7a_9fXXZDx2brODZgbqCBhZ_5Mk", new HashData((byte) 17, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("f2ea6b36c7d415accddc25d2184a0c2a").array(), Bytes.parseHex("5c82316bb6bff5f5d7643c766eb3836606ea081859ff9324").array())),
                new TestCaseHashData("AQcoq4WCXjgS-3ohwUsPoEFZ5gfctRabV6t_qogJ_8IfmMEWQGux8AE=", new HashData((byte) 7, Version.HKDF_HMAC512, Bytes.parseHex("28ab85825e3812fb7a21c14b0fa04159").array(), Bytes.parseHex("e607dcb5169b57ab7faa8809ffc21f98c116406bb1f001").array())),
                new TestCaseHashData("AQ81R7AVr4_v6IBC1TJXt9ehkabSKD5TFHqeipy5dUxvTAuJBKP5BZY=", new HashData((byte) 15, Version.HKDF_HMAC512, Bytes.parseHex("3547b015af8fefe88042d53257b7d7a1").array(), Bytes.parseHex("91a6d2283e53147a9e8a9cb9754c6f4c0b8904a3f90596").array())),
                new TestCaseHashData("Ah4PCwv_CsAJ2XKpDbfZxNBeMiPx1QrIG7vg9KsFPLZzR1lQBCQrXFxJ", new HashData((byte) 30, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("0f0b0bff0ac009d972a90db7d9c4d05e").array(), Bytes.parseHex("3223f1d50ac81bbbe0f4ab053cb67347595004242b5c5c49").array())),
                new TestCaseHashData("Ag3E0ILskrxKskzLwmcyOmVGPeE6F_naGtA8s1AGkvUC2i0LdJIRxfyI", new HashData((byte) 13, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("c4d082ec92bc4ab24ccbc267323a6546").array(), Bytes.parseHex("3de13a17f9da1ad03cb3500692f502da2d0b749211c5fc88").array())),
                new TestCaseHashData("Ah7SKwgJaaXMLEgfg8rlhmjBAsEv19IutgxZpiI6masvfMfoMEPglIF1", new HashData((byte) 30, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("d22b080969a5cc2c481f83cae58668c1").array(), Bytes.parseHex("02c12fd7d22eb60c59a6223a99ab2f7cc7e83043e0948175").array())),
                new TestCaseHashData("Ag8kL8HgOMzrQ1X17cWzvlNkSmohCw4J_QcDXQ3xRcM05Y5hYW8B6q3c", new HashData((byte) 15, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("242fc1e038cceb4355f5edc5b3be5364").array(), Bytes.parseHex("4a6a210b0e09fd07035d0df145c334e58e61616f01eaaddc").array())),
                new TestCaseHashData("ARzE8lV_cwp3rIfbZ0aVXe1RaPeD33OMkcNU3iE-0vQcxTACZrkY3cQ=", new HashData((byte) 28, Version.HKDF_HMAC512, Bytes.parseHex("c4f2557f730a77ac87db6746955ded51").array(), Bytes.parseHex("68f783df738c91c354de213ed2f41cc5300266b918ddc4").array())),
                new TestCaseHashData("ARThGmGV1PG34syaHFey_tilvPzViIXCBDDc--OIopuGmebhYuo7POY=", new HashData((byte) 20, Version.HKDF_HMAC512, Bytes.parseHex("e11a6195d4f1b7e2cc9a1c57b2fed8a5").array(), Bytes.parseHex("bcfcd58885c20430dcfbe388a29b8699e6e162ea3b3ce6").array())),
                new TestCaseHashData("Ahpb4RutZeNdwERc9aJMFW1YWSeD4498XiGRh_KEvmNzjqgwB2sUd3J_", new HashData((byte) 26, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("5be11bad65e35dc0445cf5a24c156d58").array(), Bytes.parseHex("592783e38f7c5e219187f284be63738ea830076b1477727f").array())),
                new TestCaseHashData("AQY3DxZEHF3dbxcPAhInGbP4K6Q04zqo2vLi2NCGg6KggBkYhtpzYVk=", new HashData((byte) 6, Version.HKDF_HMAC512, Bytes.parseHex("370f16441c5ddd6f170f02122719b3f8").array(), Bytes.parseHex("2ba434e33aa8daf2e2d8d08683a2a080191886da736159").array())),
                new TestCaseHashData("AgxFZXUUnWiNosuLpnFkyFL7QKSXqBsCUZUtUnnkKstlZktLrQ6VVLV1", new HashData((byte) 12, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("456575149d688da2cb8ba67164c852fb").array(), Bytes.parseHex("40a497a81b0251952d5279e42acb65664b4bad0e9554b575").array())),
                new TestCaseHashData("AhxBIPkj25HcJHSA2hPBGf3bd5E0RtEInyk4NZde1tMDdDoyjyxuK3RP", new HashData((byte) 28, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("4120f923db91dc247480da13c119fddb").array(), Bytes.parseHex("77913446d1089f293835975ed6d303743a328f2c6e2b744f").array())),
                new TestCaseHashData("AQk2Jm6RlBUG58q2YGT5GrmihwMmKDsmsr3AC1i9IBpnE0JOsgKthRk=", new HashData((byte) 9, Version.HKDF_HMAC512, Bytes.parseHex("36266e91941506e7cab66064f91ab9a2").array(), Bytes.parseHex("870326283b26b2bdc00b58bd201a6713424eb202ad8519").array())),
                new TestCaseHashData("AQvKVgVLGPCMD7nydIgnJulcPYtnIEUxmM1t8GdyiI0RuIWXVY7Di9I=", new HashData((byte) 11, Version.HKDF_HMAC512, Bytes.parseHex("ca56054b18f08c0fb9f274882726e95c").array(), Bytes.parseHex("3d8b6720453198cd6df06772888d11b88597558ec38bd2").array())),
                new TestCaseHashData("ARRdm-HjbTsGVUwQlIm-YTK0RHiNjT4GndTU-nxRz78z0rOLxnLx7WA=", new HashData((byte) 20, Version.HKDF_HMAC512, Bytes.parseHex("5d9be1e36d3b06554c109489be6132b4").array(), Bytes.parseHex("44788d8d3e069dd4d4fa7c51cfbf33d2b38bc672f1ed60").array())),
                new TestCaseHashData("AhKGixfRx7bZC3qW9NaKc-oP9bOcaDC8YLBZcngXfN3SFz153OaxqdPw", new HashData((byte) 18, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("868b17d1c7b6d90b7a96f4d68a73ea0f").array(), Bytes.parseHex("f5b39c6830bc60b0597278177cddd2173d79dce6b1a9d3f0").array())),
                new TestCaseHashData("AQv4hvUsk4r2lBo2_66zFDDyX69NlrlsIzNqLYYQ7bSVDU7MzCw-0Z0=", new HashData((byte) 11, Version.HKDF_HMAC512, Bytes.parseHex("f886f52c938af6941a36ffaeb31430f2").array(), Bytes.parseHex("5faf4d96b96c23336a2d8610edb4950d4ecccc2c3ed19d").array())),
                new TestCaseHashData("ARrkJNL0rCqXT8J5Z6tlvn9ZBKWD3oIXarRyzbhdTQEARuUxEaoMPkQ=", new HashData((byte) 26, Version.HKDF_HMAC512, Bytes.parseHex("e424d2f4ac2a974fc27967ab65be7f59").array(), Bytes.parseHex("04a583de82176ab472cdb85d4d010046e53111aa0c3e44").array())),
                new TestCaseHashData("AQ1BAc2O8E5v_seD6rUkh5K0D8TJ7UFA7DW637OhQNc1fXRjYcYbRYI=", new HashData((byte) 13, Version.HKDF_HMAC512, Bytes.parseHex("4101cd8ef04e6ffec783eab5248792b4").array(), Bytes.parseHex("0fc4c9ed4140ec35badfb3a140d7357d746361c61b4582").array())),
                new TestCaseHashData("ARmsoJJiAY3poI3XtmAwPI2iL0HnxaPbvqH3Jn9RwpnY1dIHh6jZStw=", new HashData((byte) 25, Version.HKDF_HMAC512, Bytes.parseHex("aca09262018de9a08dd7b660303c8da2").array(), Bytes.parseHex("2f41e7c5a3dbbea1f7267f51c299d8d5d20787a8d94adc").array())),
                new TestCaseHashData("AQga3wVOmjJyKviqdTPvh754J2PX4q_EScUTRaNVhFRzrh-X-CWE9hw=", new HashData((byte) 8, Version.HKDF_HMAC512, Bytes.parseHex("1adf054e9a32722af8aa7533ef87be78").array(), Bytes.parseHex("2763d7e2afc449c51345a355845473ae1f97f82584f61c").array())),
                new TestCaseHashData("AgjedB3RTkcMT2_1AyM9AOhUpJF99zW_ni1_9kJlNjR2aYfqCxauPobw", new HashData((byte) 8, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("de741dd14e470c4f6ff503233d00e854").array(), Bytes.parseHex("a4917df735bf9e2d7ff642653634766987ea0b16ae3e86f0").array())),
                new TestCaseHashData("ARRj9-2F9HOaLoBNsjVLeDF7keJPYqzowjdtrJ6XezS2br2c7uU9ERY=", new HashData((byte) 20, Version.HKDF_HMAC512, Bytes.parseHex("63f7ed85f4739a2e804db2354b78317b").array(), Bytes.parseHex("91e24f62ace8c2376dac9e977b34b66ebd9ceee53d1116").array())),
                new TestCaseHashData("AR6Fdg_zq0qT8ZY_-JIguGWVl2s8rmzkRfXxM1tUAWQx7TLyrD3plyQ=", new HashData((byte) 30, Version.HKDF_HMAC512, Bytes.parseHex("85760ff3ab4a93f1963ff89220b86595").array(), Bytes.parseHex("976b3cae6ce445f5f1335b54016431ed32f2ac3de99724").array())),
                new TestCaseHashData("ARZq-iGsFo9M2GdSDtKeRzAiAo7uJAXEgcFEVW_ZUozUWVUjF5dozXc=", new HashData((byte) 22, Version.HKDF_HMAC512, Bytes.parseHex("6afa21ac168f4cd867520ed29e473022").array(), Bytes.parseHex("028eee2405c481c144556fd9528cd4595523179768cd77").array())),
                new TestCaseHashData("AhucFM9DLZNoD6CyVC-RFiOYd5rKigyCPnPFsvZz1xY0xEOJ_AfNg12O", new HashData((byte) 27, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("9c14cf432d93680fa0b2542f91162398").array(), Bytes.parseHex("779aca8a0c823e73c5b2f673d71634c44389fc07cd835d8e").array())),
                new TestCaseHashData("ARk_-qjdDNvpRcRI6zft1AAEzawRqZDOGIXKdxaqWxb3ULi8iuc8gOo=", new HashData((byte) 25, Version.HKDF_HMAC512, Bytes.parseHex("3ffaa8dd0cdbe945c448eb37edd40004").array(), Bytes.parseHex("cdac11a990ce1885ca7716aa5b16f750b8bc8ae73c80ea").array())),
                new TestCaseHashData("AhuWGdojZcVh6MYq7ShUI0lAnQTtStMoB6gEexgOk_FE2LoVZasHh-ZW", new HashData((byte) 27, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("9619da2365c561e8c62aed2854234940").array(), Bytes.parseHex("9d04ed4ad32807a8047b180e93f144d8ba1565ab0787e656").array())),
                new TestCaseHashData("AhXav41RpF51HHX1T1zvU-UOlfv5N5x46zSooDC-j4l0EWSBD90FFxO7", new HashData((byte) 21, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("dabf8d51a45e751c75f54f5cef53e50e").array(), Bytes.parseHex("95fbf9379c78eb34a8a030be8f89741164810fdd051713bb").array())),
                new TestCaseHashData("AhUXyfuYu4YmDwTrCQVyzKYhGmMcXCJsF0gevBSkqljJTaOJIlKemh-5", new HashData((byte) 21, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("17c9fb98bb86260f04eb090572cca621").array(), Bytes.parseHex("1a631c5c226c17481ebc14a4aa58c94da38922529e9a1fb9").array())),
                new TestCaseHashData("ARFPunPhH2Un0mkxfo-HwC03x0djn8uvEiDi30jJx3F8SXJNUkck8os=", new HashData((byte) 17, Version.HKDF_HMAC512, Bytes.parseHex("4fba73e11f6527d269317e8f87c02d37").array(), Bytes.parseHex("c747639fcbaf1220e2df48c9c7717c49724d524724f28b").array())),
                new TestCaseHashData("Ah6h9_b3-Pv6gnz5v86gdp5WZF_HV4qrzudiM3i5yHqojJdOlyTRfY2z", new HashData((byte) 30, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("a1f7f6f7f8fbfa827cf9bfcea0769e56").array(), Bytes.parseHex("645fc7578aabcee7623378b9c87aa88c974e9724d17d8db3").array())),
                new TestCaseHashData("AQyLDtNdxbRtr2AQzq7TzN7mLc1ti0rk2qugN0BIr1Mq-oxfnYaYIEw=", new HashData((byte) 12, Version.HKDF_HMAC512, Bytes.parseHex("8b0ed35dc5b46daf6010ceaed3ccdee6").array(), Bytes.parseHex("2dcd6d8b4ae4daaba0374048af532afa8c5f9d8698204c").array())),
                new TestCaseHashData("ARBYNgU_K0EurNEL8PvvP2z-ROGtloSK3AtNgHpPkndoHXkxS8kmYqA=", new HashData((byte) 16, Version.HKDF_HMAC512, Bytes.parseHex("5836053f2b412eacd10bf0fbef3f6cfe").array(), Bytes.parseHex("44e1ad96848adc0b4d807a4f9277681d79314bc92662a0").array())),
                new TestCaseHashData("Ahnr_96tFwVsKfs_4ULEt2_5MqWncg-KjuCYIn0IA3SQ4pyGWtsx8-zb", new HashData((byte) 25, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("ebffdead17056c29fb3fe142c4b76ff9").array(), Bytes.parseHex("32a5a7720f8a8ee098227d08037490e29c865adb31f3ecdb").array())),
                new TestCaseHashData("AR0j_On_0oYR4PtnLdL9ZF1SRM9dZ_D3cNrAlGAMRJUMfxzn5XjYPFg=", new HashData((byte) 29, Version.HKDF_HMAC512, Bytes.parseHex("23fce9ffd28611e0fb672dd2fd645d52").array(), Bytes.parseHex("44cf5d67f0f770dac094600c44950c7f1ce7e578d83c58").array())),
                new TestCaseHashData("AQwph1FWAk3LzX7sq1j4Hs7lAzveJEnRphniiMdsnho7jdoT94c01ww=", new HashData((byte) 12, Version.HKDF_HMAC512, Bytes.parseHex("29875156024dcbcd7eecab58f81ecee5").array(), Bytes.parseHex("033bde2449d1a619e288c76c9e1a3b8dda13f78734d70c").array())),
                new TestCaseHashData("AhKKeml4kyQCKdGR0w7fbY-knzCOhRI9PY0-1LDEWlR3gzAYsFKRBGaE", new HashData((byte) 18, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("8a7a697893240229d191d30edf6d8fa4").array(), Bytes.parseHex("9f308e85123d3d8d3ed4b0c45a5477833018b05291046684").array())),
                new TestCaseHashData("AQX5JgbVvxFclYCzQO92Gnf_dWps5ljTb_Yut04dJTp6DqtsHFH2MzE=", new HashData((byte) 5, Version.HKDF_HMAC512, Bytes.parseHex("f92606d5bf115c9580b340ef761a77ff").array(), Bytes.parseHex("756a6ce658d36ff62eb74e1d253a7a0eab6c1c51f63331").array())),
                new TestCaseHashData("AhW6Rg7BIgPa62f7PDWYBgXvzVWvXCDdIGO18hl79KCUtfI87cP6kNHA", new HashData((byte) 21, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("ba460ec12203daeb67fb3c35980605ef").array(), Bytes.parseHex("cd55af5c20dd2063b5f2197bf4a094b5f23cedc3fa90d1c0").array())),
                new TestCaseHashData("AR2isFKFaKaoZLeoOUANkPw5XPozoopzPPAYgVL5QGRcveGcGjvfLwU=", new HashData((byte) 29, Version.HKDF_HMAC512, Bytes.parseHex("a2b0528568a6a864b7a839400d90fc39").array(), Bytes.parseHex("5cfa33a28a733cf0188152f940645cbde19c1a3bdf2f05").array())),
                new TestCaseHashData("Ah2wvQicJuob65AjRFDAwpVLuY-NEU3sEf7nNWoz5cGu8j5rW7g1oW9a", new HashData((byte) 29, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("b0bd089c26ea1beb90234450c0c2954b").array(), Bytes.parseHex("b98f8d114dec11fee7356a33e5c1aef23e6b5bb835a16f5a").array())),
                new TestCaseHashData("ARRGx8jdme9Q7NHGvx6U1H4Nm9fW-ko-uI49Ws1LUvDELk45bRdug04=", new HashData((byte) 20, Version.HKDF_HMAC512, Bytes.parseHex("46c7c8dd99ef50ecd1c6bf1e94d47e0d").array(), Bytes.parseHex("9bd7d6fa4a3eb88e3d5acd4b52f0c42e4e396d176e834e").array())),
                new TestCaseHashData("ARuwkZVdkAiiNd8lMV_97RoKbKrYlf18fS2xjgOxjtaV3kCcX8wurWQ=", new HashData((byte) 27, Version.HKDF_HMAC512, Bytes.parseHex("b091955d9008a235df25315ffded1a0a").array(), Bytes.parseHex("6caad895fd7c7d2db18e03b18ed695de409c5fcc2ead64").array())),
                new TestCaseHashData("AQzZKUz3sTsUedQNdfcNfBWSPKqAwwW1aFj1A0CXFumgAYx8Pw9LXS0=", new HashData((byte) 12, Version.HKDF_HMAC512, Bytes.parseHex("d9294cf7b13b1479d40d75f70d7c1592").array(), Bytes.parseHex("3caa80c305b56858f503409716e9a0018c7c3f0f4b5d2d").array())),
                new TestCaseHashData("ARCuMKbkcvzoNiPySYSCwUFGBEWndRvMufsUqM2ijff58IUBcQTmEqE=", new HashData((byte) 16, Version.HKDF_HMAC512, Bytes.parseHex("ae30a6e472fce83623f2498482c14146").array(), Bytes.parseHex("0445a7751bccb9fb14a8cda28df7f9f085017104e612a1").array())),
                new TestCaseHashData("ARhni6C-03caM2jxa3SFr02RsLXsLkg_EAr2reBwxfqfNY99jRagMrU=", new HashData((byte) 24, Version.HKDF_HMAC512, Bytes.parseHex("678ba0bed3771a3368f16b7485af4d91").array(), Bytes.parseHex("b0b5ec2e483f100af6ade070c5fa9f358f7d8d16a032b5").array())),
                new TestCaseHashData("ARptnv0VeDxWQmQNVyLiaZLXbNZTfkde71I0ef9Oq76JNE9F8zPeis0=", new HashData((byte) 26, Version.HKDF_HMAC512, Bytes.parseHex("6d9efd15783c5642640d5722e26992d7").array(), Bytes.parseHex("6cd6537e475eef523479ff4eabbe89344f45f333de8acd").array())),
                new TestCaseHashData("AQr_GnX1dT-PrSOFBzrcrjXNnZUiwEXqRnm0nRM9BmM13neGqNVNbN4=", new HashData((byte) 10, Version.HKDF_HMAC512, Bytes.parseHex("ff1a75f5753f8fad2385073adcae35cd").array(), Bytes.parseHex("9d9522c045ea4679b49d133d066335de7786a8d54d6cde").array())),
                new TestCaseHashData("AhjqnmS0a3f1dTxRHT57xaI6XoxxNlZjRbjBhanrFiBh8sRxu1FRGcLs", new HashData((byte) 24, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("ea9e64b46b77f5753c511d3e7bc5a23a").array(), Bytes.parseHex("5e8c7136566345b8c185a9eb162061f2c471bb515119c2ec").array())),
                new TestCaseHashData("Agz2Show3aUR-xZIm5MRuDmYB9YNa1GeXmji6pzm2RjXyFzN8rrxXlZp", new HashData((byte) 12, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("f64a1a30dda511fb16489b9311b83998").array(), Bytes.parseHex("07d60d6b519e5e68e2ea9ce6d918d7c85ccdf2baf15e5669").array())),
                new TestCaseHashData("AhZlm9rqz7JE_XO7bHUVn6KK7BmKmonY2PVnTqkJ9vNzQW6DbNMJas-y", new HashData((byte) 22, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("659bdaeacfb244fd73bb6c75159fa28a").array(), Bytes.parseHex("ec198a9a89d8d8f5674ea909f6f373416e836cd3096acfb2").array())),
                new TestCaseHashData("AQf70t5fgVfwkHBlt4n-45EqjPDY53M9tfOXFugHt-07otQeKRJijn0=", new HashData((byte) 7, Version.HKDF_HMAC512, Bytes.parseHex("fbd2de5f8157f0907065b789fee3912a").array(), Bytes.parseHex("8cf0d8e7733db5f39716e807b7ed3ba2d41e2912628e7d").array())),
                new TestCaseHashData("Ahu37n766PApRpwIfR8AmltijGX3jz50IQDzX-rdW7GKwRriCOjBujlf", new HashData((byte) 27, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("b7ee7efae8f029469c087d1f009a5b62").array(), Bytes.parseHex("8c65f78f3e742100f35feadd5bb18ac11ae208e8c1ba395f").array())),
                new TestCaseHashData("AgWNVG_Ol8t71P6FAL8dyHZB3z_Ozv8XIUO8LniCMeBR7QMTZk_RZppG", new HashData((byte) 5, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("8d546fce97cb7bd4fe8500bf1dc87641").array(), Bytes.parseHex("df3fceceff172143bc2e788231e051ed0313664fd1669a46").array())),
                new TestCaseHashData("Ah2EdERV3ZZa5uEmfDcyi7iikcSRmFIJcoPL3AhL2a7xEb4g7mmXmwv_", new HashData((byte) 29, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("84744455dd965ae6e1267c37328bb8a2").array(), Bytes.parseHex("91c4919852097283cbdc084bd9aef111be20ee69979b0bff").array())),
                new TestCaseHashData("AhOyG4-coh0yfYOcNf_HQmr8oV8UA7BPDDv5e4jfwYOb2tubil4eGrGG", new HashData((byte) 19, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("b21b8f9ca21d327d839c35ffc7426afc").array(), Bytes.parseHex("a15f1403b04f0c3bf97b88dfc1839bdadb9b8a5e1e1ab186").array())),
                new TestCaseHashData("AhBjjfS0mPQjDI9K3ekTxys-2NO64BgziApNmcvQAU8MFwp0WCF7Ntb3", new HashData((byte) 16, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("638df4b498f4230c8f4adde913c72b3e").array(), Bytes.parseHex("d8d3bae01833880a4d99cbd0014f0c170a7458217b36d6f7").array())),
                new TestCaseHashData("AQtPDN7rGCB13GTipzMC8ThkE9SwoZ7vuwdyN81amp89VumNwDv-lP0=", new HashData((byte) 11, Version.HKDF_HMAC512, Bytes.parseHex("4f0cdeeb182075dc64e2a73302f13864").array(), Bytes.parseHex("13d4b0a19eefbb077237cd5a9a9f3d56e98dc03bfe94fd").array())),
                new TestCaseHashData("AQzS19lAeJpYYGutBla0xJiEe-8DLhwcKTdeFPnml6GcM-r2aahEAxU=", new HashData((byte) 12, Version.HKDF_HMAC512, Bytes.parseHex("d2d7d940789a58606bad0656b4c49884").array(), Bytes.parseHex("7bef032e1c1c29375e14f9e697a19c33eaf669a8440315").array())),
                new TestCaseHashData("Ah0VWCBQYUAJzxK_TiepupPUM0h8meT-k9ahdzdcJoIjKud1xjf2Uvqh", new HashData((byte) 29, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("15582050614009cf12bf4e27a9ba93d4").array(), Bytes.parseHex("33487c99e4fe93d6a177375c2682232ae775c637f652faa1").array())),
                new TestCaseHashData("AhRNHnB53M6LVV0DySeB5OGk2AqiUAqwUDbP1zNEujwd_DlkFkjGG0rP", new HashData((byte) 20, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("4d1e7079dcce8b555d03c92781e4e1a4").array(), Bytes.parseHex("d80aa2500ab05036cfd73344ba3c1dfc39641648c61b4acf").array())),
                new TestCaseHashData("Ah10uHMcPXa4qM5OPcrpaDdlo5CtEsZ9pCuDiFNNsiNeN7bEEQwmxQlT", new HashData((byte) 29, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("74b8731c3d76b8a8ce4e3dcae9683765").array(), Bytes.parseHex("a390ad12c67da42b8388534db2235e37b6c4110c26c50953").array())),
                new TestCaseHashData("AQZWDroZ3Ogyj5N1OCDmR35A8-XA0WBkh4Sr7WPxfJpwlfpr7dd6FnE=", new HashData((byte) 6, Version.HKDF_HMAC512, Bytes.parseHex("560eba19dce8328f93753820e6477e40").array(), Bytes.parseHex("f3e5c0d160648784abed63f17c9a7095fa6bedd77a1671").array())),
                new TestCaseHashData("AR7X56EdeWKyFD32hba2_dyDisv7JXXGbGUeeCeIqPiVoBMOlTOVzS0=", new HashData((byte) 30, Version.HKDF_HMAC512, Bytes.parseHex("d7e7a11d7962b2143df685b6b6fddc83").array(), Bytes.parseHex("8acbfb2575c66c651e782788a8f895a0130e953395cd2d").array())),
                new TestCaseHashData("AhU-6TuOanNXNGF3vCFK-UnOY0grOL7jKAykPXB8LH_1_CBTRU0i6X_F", new HashData((byte) 21, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("3ee93b8e6a7357346177bc214af949ce").array(), Bytes.parseHex("63482b38bee3280ca43d707c2c7ff5fc2053454d22e97fc5").array())),
                new TestCaseHashData("AguqMN3EmNiKFeqUZ_SLo4Bmel7r5ptoKgWFjKKuuSgRF58pR4VZlrlE", new HashData((byte) 11, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("aa30ddc498d88a15ea9467f48ba38066").array(), Bytes.parseHex("7a5eebe69b682a05858ca2aeb92811179f2947855996b944").array())),
                new TestCaseHashData("Agy_PyFhkvs-kEgWbYJvBIeLhX9ctspYCCIBVA_XWMtnHMWcpdV1O3c3", new HashData((byte) 12, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("bf3f216192fb3e9048166d826f04878b").array(), Bytes.parseHex("857f5cb6ca58082201540fd758cb671cc59ca5d5753b7737").array())),
                new TestCaseHashData("AhRUQ200LnQ4iYNAFIMFSK563BgsoK-0e4EZ8XcaxlSgjdPN5K1G9ptd", new HashData((byte) 20, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("54436d342e743889834014830548ae7a").array(), Bytes.parseHex("dc182ca0afb47b8119f1771ac654a08dd3cde4ad46f69b5d").array())),
                new TestCaseHashData("AQmiIMV6yge3oRavF62SALXdwHjtWOoes4XCIfTvN9wIZS9TmHkzA_M=", new HashData((byte) 9, Version.HKDF_HMAC512, Bytes.parseHex("a220c57aca07b7a116af17ad9200b5dd").array(), Bytes.parseHex("c078ed58ea1eb385c221f4ef37dc08652f5398793303f3").array())),
                new TestCaseHashData("ARkhCLZN95aRBw5b3arrvVgYt0OfBL6vXUvppOi9SmkdCZfKiwoltxo=", new HashData((byte) 25, Version.HKDF_HMAC512, Bytes.parseHex("2108b64df79691070e5bddaaebbd5818").array(), Bytes.parseHex("b7439f04beaf5d4be9a4e8bd4a691d0997ca8b0a25b71a").array())),
                new TestCaseHashData("AQX67dm2QqPviz-dcXFynPM5ztC5MGzTerSeo9BrDtair73hV2tyhw0=", new HashData((byte) 5, Version.HKDF_HMAC512, Bytes.parseHex("faedd9b642a3ef8b3f9d7171729cf339").array(), Bytes.parseHex("ced0b9306cd37ab49ea3d06b0ed6a2afbde1576b72870d").array())),
                new TestCaseHashData("AgdFyDEf_miZgQEDGSaQtluzW_JSy1c70MLIGJpCUBWHDELbdvjRhqQS", new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("45c8311ffe6899810103192690b65bb3").array(), Bytes.parseHex("5bf252cb573bd0c2c8189a425015870c42db76f8d186a412").array())),
                new TestCaseHashData("ARXkfT-BZQ3_cX9pP6FgPK93xBho0pZjvEFWefWbFAg0-7IWa_lM7_k=", new HashData((byte) 21, Version.HKDF_HMAC512, Bytes.parseHex("e47d3f81650dff717f693fa1603caf77").array(), Bytes.parseHex("c41868d29663bc415679f59b140834fbb2166bf94ceff9").array())),
                new TestCaseHashData("AghO0Ucarig-tic2D3ijJVnTc6V6F7gMpMlV4ncF8Amc4nnyk6KQMbbX", new HashData((byte) 8, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("4ed1471aae283eb627360f78a32559d3").array(), Bytes.parseHex("73a57a17b80ca4c955e27705f0099ce279f293a29031b6d7").array())),
                new TestCaseHashData("AQXDr6lCrdlEPqTYO89w5udA2Od_kyjVX4HneC3VDK1APbYKDLKx4Gs=", new HashData((byte) 5, Version.HKDF_HMAC512, Bytes.parseHex("c3afa942add9443ea4d83bcf70e6e740").array(), Bytes.parseHex("d8e77f9328d55f81e7782dd50cad403db60a0cb2b1e06b").array())),
                new TestCaseHashData("AgmyaQmFXEx-4zLAkX7g-lpYv-U6G8muNbGDOPjM00OjFsN2TMNzbXL7", new HashData((byte) 9, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("b26909855c4c7ee332c0917ee0fa5a58").array(), Bytes.parseHex("bfe53a1bc9ae35b18338f8ccd343a316c3764cc3736d72fb").array())),
                new TestCaseHashData("AQedK59Ivvx_apEViL9lYPBHW-3hgLmW2FuGFPYdFpkdQrsuAsz7gKo=", new HashData((byte) 7, Version.HKDF_HMAC512, Bytes.parseHex("9d2b9f48befc7f6a911588bf6560f047").array(), Bytes.parseHex("5bede180b996d85b8614f61d16991d42bb2e02ccfb80aa").array())),
                new TestCaseHashData("AQ7A0SvtvnCoW_zw5N5rvl6yigeyEwEJEr3s6PtsWsT_Y2ypWwnta9U=", new HashData((byte) 14, Version.HKDF_HMAC512, Bytes.parseHex("c0d12bedbe70a85bfcf0e4de6bbe5eb2").array(), Bytes.parseHex("8a07b213010912bdece8fb6c5ac4ff636ca95b09ed6bd5").array())),
                new TestCaseHashData("AREvpKCn5XQaMFPp7KD_-kLvcug6aqhHwE0yr9sQo_sFXzmb6eoe49o=", new HashData((byte) 17, Version.HKDF_HMAC512, Bytes.parseHex("2fa4a0a7e5741a3053e9eca0fffa42ef").array(), Bytes.parseHex("72e83a6aa847c04d32afdb10a3fb055f399be9ea1ee3da").array())),
                new TestCaseHashData("Ag5CSXmXZGae3RXc0TdkTkr_99uT6u0MaM1fNmxen09IT-jUWGrSX7rj", new HashData((byte) 14, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("4249799764669edd15dcd137644e4aff").array(), Bytes.parseHex("f7db93eaed0c68cd5f366c5e9f4f484fe8d4586ad25fbae3").array())),
                new TestCaseHashData("ARcNzqsS5c6OtynOBVT1AbeAJbbxJqy3Q5UoJgStPGywCdHcJtL34xM=", new HashData((byte) 23, Version.HKDF_HMAC512, Bytes.parseHex("0dceab12e5ce8eb729ce0554f501b780").array(), Bytes.parseHex("25b6f126acb74395282604ad3c6cb009d1dc26d2f7e313").array())),
                new TestCaseHashData("ARa_xJJSlplpWUJRBgxyzNW39Jpj6VCejh3hzBefq4nIzC6hQQLaFT4=", new HashData((byte) 22, Version.HKDF_HMAC512, Bytes.parseHex("bfc49252969969594251060c72ccd5b7").array(), Bytes.parseHex("f49a63e9509e8e1de1cc179fab89c8cc2ea14102da153e").array())),
                new TestCaseHashData("AR2XrXr21lCZtwcE1LA6GJWeYG2uIB0x0ewHjsVP253O_0u2PlyEydw=", new HashData((byte) 29, Version.HKDF_HMAC512, Bytes.parseHex("97ad7af6d65099b70704d4b03a18959e").array(), Bytes.parseHex("606dae201d31d1ec078ec54fdb9dceff4bb63e5c84c9dc").array())),
                new TestCaseHashData("AQcj07JN8i26MseZwRl8mXqXjq5z4j5dEAqjr22ivyqywqNOS_ysPKI=", new HashData((byte) 7, Version.HKDF_HMAC512, Bytes.parseHex("23d3b24df22dba32c799c1197c997a97").array(), Bytes.parseHex("8eae73e23e5d100aa3af6da2bf2ab2c2a34e4bfcac3ca2").array())),
                new TestCaseHashData("AgfD1ofCbInA0An6-LXGm2yPH03E6TSbiELaH7EZx_xwbRGbMfEWTRZe", new HashData((byte) 7, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("c3d687c26c89c0d009faf8b5c69b6c8f").array(), Bytes.parseHex("1f4dc4e9349b8842da1fb119c7fc706d119b31f1164d165e").array())),
                new TestCaseHashData("AhUmbmzvE2OayM_sRK4rXIVqWF4bo5ed3KSdfC81mbPjaQMR4XdRJ8u0", new HashData((byte) 21, Version.HKDF_HMAC512_BCRYPT_24_BYTE, Bytes.parseHex("266e6cef13639ac8cfec44ae2b5c856a").array(), Bytes.parseHex("585e1ba3979ddca49d7c2f3599b3e3690311e1775127cbb4").array())),
        };

        for (TestCaseHashData testDatum : testData) {
            assertEquals(testDatum.hashData, HashData.parse(testDatum.base64Encoded));
            assertEquals(testDatum.base64Encoded, testDatum.hashData.getAsEncodedMessageFormat());
            assertEquals(testDatum.hashData, HashData.parse(Bytes.parseBase64(testDatum.base64Encoded).array()));
            assertArrayEquals(testDatum.hashData.getAsBlobMessageFormat(), Bytes.parseBase64(testDatum.base64Encoded).array());
        }
    }

    //@Test
    public void createRefHashData() {
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
