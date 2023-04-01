# BCrypt based Key Derivation Function (BKDF)

[![Maven Central](https://img.shields.io/maven-central/v/at.favre.lib/bkdf)](https://mvnrepository.com/artifact/at.favre.lib/bkdf)
[![Github Actions](https://github.com/patrickfav/bkdf/actions/workflows/build_deploy.yml/badge.svg)](https://github.com/patrickfav/bkdf/actions)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/bkdf.svg)](https://www.javadoc.io/doc/at.favre.lib/bkdf)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bkdf&metric=coverage)](https://sonarcloud.io/summary/new_code?id=patrickfav_bkdf)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bkdf&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=patrickfav_bkdf)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=patrickfav_bkdf&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=patrickfav_bkdf)

The aim of this project is to improve on the cryptographic primitive [BCrypt](https://en.wikipedia.org/wiki/Bcrypt) with
providing well-defined modes of operation which includes:

* Improved password hashing function
* Protocol to upgrade password hashes offline
* Fully functional key derivation function

All this is achieved by only adding [HKDF](https://en.wikipedia.org/wiki/HKDF) as additional building block.

The code is compiled with target [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications.

_Note, that this project is ongoing research and may not be ready for prime-time yet as it requires more feedback from the cryptographic community._

## Quickstart

Add dependency to your `pom.xml` ([check latest release](https://github.com/patrickfav/bkdf/releases)):

```xml
<dependency>
    <groupId>at.favre.lib</groupId>
    <artifactId>bkdf</artifactId>
    <version>{latest-version}</version>
</dependency>
```

A very simple example using the password hasher:

```java
PasswordHasher hasher = BKDF.createPasswordHasher();

char[] pw = "secret".toCharArray();
int costFactor = 6; // same as with bcrypt 4-31 doubling the iterations every increase

//returns base64 url-safe encoded string
String hash = hasher.hash(pw, costFactor);

PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
boolean verified = verifier.verify(pw, hash);
```

### Full Example

The BKDF protocol supports 3 use-cases:

* password hash with key stretching feature for storage
* upgrade of previously generated password hashes offline without the user password
* key derivation function with key strechting feature to generate high quality keying material (for e.g. secret keys)

#### Password Hash

A password hash is used to generate a hash from a user-password which can't easily be used to calculate the used password without brute-forcing. An important feature of password hashes are, that they are slow, so it makes it harder (or infeasible) for an attacker to brute force. This property is also called "[key-stretching](https://en.wikipedia.org/wiki/Key_stretching)". Well known password hashes are [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), [scrypt](https://en.wikipedia.org/wiki/Scrypt) and [Argon2](https://en.wikipedia.org/wiki/Argon2).

```java
// provide different version of hash config and provide own impl of secure random for salt gen
PasswordHasher hasher = BKDF.createPasswordHasher(Version.HKDF_HMAC512, new SecureRandom());
char[] pw = "secret".toCharArray();
HashData hashData = hasher.hashRaw("secret".toCharArray(), 4);

// get the raw, non-encoded hash message
byte[] hashMsgAsBlob = hashData.getAsBlobMessageFormat();

// get the base64 url-safe encoded string
String hashAsBase64 = hashData.getAsEncodedMessageFormat();

PasswordHashVerifier verifier = BKDF.createPasswordHashVerifier();
boolean verified = verifier.verify(pw, hashData);
```

#### Password Hash Upgrade

BCrypt does not support upgrading the strength of the password hash without the user password. Having legacy password hashes in a DB, the need may arise to improve them, because CPU performance increased of the last couple of years. With this feature a password can be upgraded offline by basically chaining multiple hashes together.

This mode will chain a specific new hash with given cost factor:

```java
char[] pw = "secret".toCharArray();

// hash with cost factor 5
String hash = BKDF.createPasswordHasher().hash(pw, 5);
        PasswordHashUpgrader upgrader=new PasswordHashUpgrader.Default(new SecureRandom());

// upgrade hash with an additional cost factor (i.e. now needs to calculate 5 + 6 = 32 + 64 = 96 iterations
        CompoundHashData compoundHashData=upgrader.upgradePasswordHashWith(6,hash);

// create base64 url-safe encoded msg and verify
boolean verified = BKDF.createPasswordHashVerifier().verify(pw, compoundHashData.getAsEncodedMessageFormat());
```

Another mode will take a target cost factor and calculate the required hashes to achieve it

```java
char[] pw = "secret".toCharArray();

// hash with cost factor 5
String hash = BKDF.createPasswordHasher().hash(pw, 5);
PasswordHashUpgrader upgrader = new PasswordHashUpgrader.Default(new SecureRandom());

// upgrade to have exactly cost factor 8 (aka 2^8 = 256 iterations)
CompoundHashData compoundHashData = upgrader.upgradePasswordHashTo(8, hash);

// create base64 url-safe encoded msg and verify
boolean verified = BKDF.createPasswordHashVerifier().verify(pw, compoundHashData.getAsEncodedMessageFormat());
```

#### Key Derivation Function
It might be useful to have a primitive that generates high-quality key material for e.g. symmetric encryption and not password hashes.

This example creates an AES key from a user password: 

```java
char[] pw = "secret".toCharArray();
byte[] salt = Bytes.random(16).array();
int costFactor = 5;

KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);
byte[] aesKey = kdf.derive(salt, pw, costFactor, Bytes.from("aes-key").array(), 16);

SecretKey aesSecretKey = new SecretKeySpec(aesKey, "AES");
```

To generate multiple keys, use the following example, so you are not required to generate the internal bcrypt hash for every key: 

```java
// an entropy source used in your current protocol
byte[]ikm=Bytes.random(12).array();
byte[] salt = Bytes.random(16).array();
int costFactor = 5;

KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.HKDF_HMAC512);
List<KeyDerivationFunction.KdfConfig> config = Arrays.asList(
        new KeyDerivationFunction.KdfConfig(Bytes.from("aes-key").array(), 16),
        new KeyDerivationFunction.KdfConfig(Bytes.from("mac-key").array(), 32)
);
List<byte[]> keys = kdf.deriveMulti(salt, ikm, costFactor, config);

SecretKey aesSecretKey = new SecretKeySpec(keys.get(0), "AES");
SecretKey macSecretKey = new SecretKeySpec(keys.get(1), "HmacSHA512");
```

## Description

In the following the details of each of the protocols are discussed.

In the example the following functions are used:

    bcrypt(cost_factor {4-31}, user_pw, [16-byte-salt])
    hkdf_extract(salt, input_key_material)
    hkdf_expand(output_key_material, info_param, out_length_byte)

The [HMAC](https://en.wikipedia.org/wiki/HMAC) used by [HKDF](https://tools.ietf.org/html/rfc5869) is defined by the used hash version, currently only HMAC-SHA512 is supported.

### Password Hash Protocol

#### Step 1: Extract User Password

First create uniformly distributed entropy byte string with through HKDF "extract" from user password. Convert the user password to a byte array using UTF-8 encoding. Use an empty byte array as salt with the length of the underyling hash output length (aka HMAC-SHA512 == 64 byte)

    utf8PwBytes = user_password.getUtf8Bytes()
    extractedPw = hkdf_extract(empty_byte_array, utf8PwBytes)
   
#### Step 2: Stretch with BCrypt

tbd.

### Password Upgrade Protocol

tbd.

### KDF Protocol

tbd.

## Download

The artifacts are deployed to [Maven Central](https://search.maven.org/).

### Maven

Add dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>at.favre.lib</groupId>
    <artifactId>bkdf</artifactId>
    <version>{latest-version}</version>
</dependency>
```

### Gradle

Add to your `build.gradle` module dependencies:

    compile group: 'at.favre.lib', name: 'bkdf', version: '{latest-version}'

### Local Jar

[Grab jar from the latest release.](https://github.com/patrickfav/bkdf/releases/latest)

## Security Relevant Information

### OWASP Dependency Check

This project uses the [OWASP Dependency-Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) which is a utility that identifies project dependencies and checks if there are any known, publicly disclosed, vulnerabilities against a [NIST database](https://nvd.nist.gov/vuln/data-feeds).
The build will fail if any issue is found.

### Digital Signatures

#### Signed Jar

The provided JARs in the GitHub release page are signed with my private key:

    CN=Patrick Favre-Bulle, OU=Private, O=PF Github Open Source, L=Vienna, ST=Vienna, C=AT
    Validity: Thu Sep 07 16:40:57 SGT 2017 to: Fri Feb 10 16:40:57 SGT 2034
    SHA1: 06:DE:F2:C5:F7:BC:0C:11:ED:35:E2:0F:B1:9F:78:99:0F:BE:43:C4
    SHA256: 2B:65:33:B0:1C:0D:2A:69:4E:2D:53:8F:29:D5:6C:D6:87:AF:06:42:1F:1A:EE:B3:3C:E0:6D:0B:65:A1:AA:88

Use the jarsigner tool (found in your `$JAVA_HOME/bin` folder) folder to verify.

#### Signed Commits

All tags and commits by me are signed with git with my private key:

    GPG key ID: 4FDF85343912A3AB
    Fingerprint: 2FB392FB05158589B767960C4FDF85343912A3AB

## Build

### Jar Sign

If you want to jar sign you need to provide a file `keystore.jks` in the
root folder with the correct credentials set in environment variables (
`OPENSOURCE_PROJECTS_KS_PW` and `OPENSOURCE_PROJECTS_KEY_PW`); alias is
set as `pfopensource`.

If you want to skip jar signing just change the skip configuration in the
`pom.xml` jar sign plugin to true:

    <skip>true</skip>

### Build with Maven

Use the Maven wrapper to create a jar including all dependencies

    mvnw clean install

### Checkstyle Config File

This project uses my [`common-parent`](https://github.com/patrickfav/mvn-common-parent) which centralized a lot of
the plugin versions aswell as providing the checkstyle config rules. Specifically they are maintained in [`checkstyle-config`](https://github.com/patrickfav/checkstyle-config). Locally the files will be copied after you `mvnw install` into your `target` folder and is called
`target/checkstyle-checker.xml`. So if you use a plugin for your IDE, use this file as your local configuration.

## Tech-Stack

* Java 7 (+ [errorprone](https://github.com/google/error-prone) static analyzer)
* Maven

## Related Libraries

* [BCyrpt Password Hash Function (Java)](https://github.com/patrickfav/bcrypt)
* [HKDF [RFC5869] Two-Step KDF (Java)](https://github.com/patrickfav/hkdf)
* [Single Step KDF [NIST SP 800-56C] (Java)](https://github.com/patrickfav/singlestep-kdf)

# License

Copyright 2018 Patrick Favre-Bulle

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
