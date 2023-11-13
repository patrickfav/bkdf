module at.favre.lib {
    requires at.favre.lib.hkdf;
    requires at.favre.lib.bytes;
    requires bcrypt;
    exports at.favre.lib.crypto.bkdf;
}