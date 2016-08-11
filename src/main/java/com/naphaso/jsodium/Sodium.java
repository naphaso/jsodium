package com.naphaso.jsodium;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Locale;

/**
 * Created by wolong on 18/07/16.
 */
public final class Sodium {
    static {
        String os = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
        if(os.contains("win")) {
            //loadLibrary("libjsodium.dll");
            throw new RuntimeException("failed to load jsodium, OS isn't supported");
        } else if(os.contains("mac") || os.contains("darwin")) {
            loadLibrary("libjsodium.dylib");
        } else if(os.contains("linux")) {
            loadLibrary("libjsodium.so");
        } else {
            throw new RuntimeException("failed to load jsodium, OS isn't supported");
        }

        Sodium.sodium_init();
    }

    private static void loadLibrary(String file) {
        final String[] parts = file.split("\\.", 2);
        final String name = parts[0];
        final String extension = parts[1];


        try {
            final File tempFile = File.createTempFile(name, extension);
            tempFile.deleteOnExit();

            try(
                    InputStream inputStream = Sodium.class.getClassLoader().getResourceAsStream(file);
                    OutputStream outputStream = new FileOutputStream(tempFile)
            ) {
                byte[] buffer = new byte[4096];
                int len;
                while((len = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, len);
                }
            }

            System.load(tempFile.getAbsolutePath());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //#include "sodium/core.h"
    public static native int sodium_init();

    //#include "sodium/crypto_aead_aes256gcm.h"
    public static final int crypto_aead_aes256gcm_KEYBYTES = 32;
    public static final int crypto_aead_aes256gcm_NSECBYTES = 0;
    public static final int crypto_aead_aes256gcm_NPUBBYTES = 12;
    public static final int crypto_aead_aes256gcm_ABYTES = 16;

    public static native int crypto_aead_aes256gcm_is_available();

    public static native int crypto_aead_aes256gcm_encrypt(
                                                            byte[] ciphertext,
                                                            byte[] confidentialMessage,
                                                            byte[] publicMessage,
                                                            byte[] nonce,
                                                            byte[] key);
    public static native int crypto_aead_aes256gcm_decrypt(
                                                            byte[] plaintext,
                                                            byte[] confidentialMessage,
                                                            byte[] publicMessage,
                                                            byte[] nonce,
                                                            byte[] key);

    public static native int crypto_aead_aes256gcm_encrypt_detached();
    public static native int crypto_aead_aes256gcm_decrypt_detached();
    public static native int crypto_aead_aes256gcm_beforenm();
    public static native int crypto_aead_aes256gcm_encrypt_afternm();
    public static native int crypto_aead_aes256gcm_decrypt_afternm();
    public static native int crypto_aead_aes256gcm_encrypt_detached_afternm();
    public static native int crypto_aead_aes256gcm_decrypt_detached_afternm();


    //#include "sodium/crypto_aead_chacha20poly1305.h"
    public static final int crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
    public static final int crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;
    public static final int crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
    public static final int crypto_aead_chacha20poly1305_ietf_ABYTES = 16;

    public static native int crypto_aead_chacha20poly1305_ietf_encrypt(byte[] ciphertext,
                                                                       byte[] confidentialMessage,
                                                                       byte[] publicMessage,
                                                                       byte[] nonce,
                                                                       byte[] key);
    public static native int crypto_aead_chacha20poly1305_ietf_decrypt(byte[] plaintext,
                                                                       byte[] confidentialMessage,
                                                                       byte[] publicMessage,
                                                                       byte[] nonce,
                                                                       byte[] key);
    public static native int crypto_aead_chacha20poly1305_ietf_encrypt_detached();
    public static native int crypto_aead_chacha20poly1305_ietf_decrypt_detached();

    public static final int crypto_aead_chacha20poly1305_KEYBYTES = 32;
    public static final int crypto_aead_chacha20poly1305_NSECBYTES = 0;
    public static final int crypto_aead_chacha20poly1305_NPUBBYTES = 8;
    public static final int crypto_aead_chacha20poly1305_ABYTES = 16;

    public static native int crypto_aead_chacha20poly1305_encrypt(byte[] ciphertext,
                                                                  byte[] confidentialMessage,
                                                                  byte[] publicMessage,
                                                                  byte[] nonce,
                                                                  byte[] key);
    public static native int crypto_aead_chacha20poly1305_decrypt(byte[] plaintext,
                                                                  byte[] confidentialMessage,
                                                                  byte[] publicMessage,
                                                                  byte[] nonce,
                                                                  byte[] key);
    public static native int crypto_aead_chacha20poly1305_encrypt_detached();
    public static native int crypto_aead_chacha20poly1305_decrypt_detached();

    public static final int crypto_aead_chacha20poly1305_IETF_KEYBYTES = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
    public static final int crypto_aead_chacha20poly1305_IETF_NSECBYTES = crypto_aead_chacha20poly1305_ietf_NSECBYTES;
    public static final int crypto_aead_chacha20poly1305_IETF_NPUBBYTES = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    public static final int crypto_aead_chacha20poly1305_IETF_ABYTES = crypto_aead_chacha20poly1305_ietf_ABYTES;

    //#include "sodium/crypto_auth_hmacsha512256.h"

    public static final int crypto_auth_hmacsha512256_BYTES = 32;
    public static final int crypto_auth_hmacsha512256_KEYBYTES = 32;

    public static native int crypto_auth_hmacsha512256(byte[] out, byte[] in, byte[] key);
    public static native int crypto_auth_hmacsha512256_verify(byte[] hash, byte[] in, byte[] key);

    public static native int crypto_auth_hmacsha512256_statebytes();
    public static native int crypto_auth_hmacsha512256_init(byte[] state, byte[] key);
    public static native int crypto_auth_hmacsha512256_update(byte[] state, byte[] in);
    public static native int crypto_auth_hmacsha512256_final(byte[] state, byte[] out);

    //#include "sodium/crypto_auth.h"

    public static final int crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES;
    public static final int crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES;
    public static final String crypto_auth_PRIMITIVE = "hmacsha512256";

    public static native int crypto_auth(byte[] out, byte[] in, byte[] key);
    public static native int crypto_auth_verify(byte[] hash, byte[] in, byte[] key);


    //#include "sodium/crypto_auth_hmacsha256.h"

    public static final int crypto_auth_hmacsha256_BYTES = 32;
    public static final int crypto_auth_hmacsha256_KEYBYTES = 32;

    public static native int crypto_auth_hmacsha256(byte[] out, byte[] in, byte[] key);
    public static native int crypto_auth_hmacsha256_verify(byte[] hash, byte[] in, byte[] key);

    public static native int crypto_auth_hmacsha256_statebytes();
    public static native int crypto_auth_hmacsha256_init(byte[] state, byte[] key);
    public static native int crypto_auth_hmacsha256_update(byte[] state, byte[] in);
    public static native int crypto_auth_hmacsha256_final(byte[] state, byte[] out);

    //#include "sodium/crypto_auth_hmacsha512.h"

    public static final int crypto_auth_hmacsha512_BYTES = 64;
    public static final int crypto_auth_hmacsha512_keybytes = 32;

    public static native int crypto_auth_hmacsha512(byte[] out, byte[] in, byte[] key);
    public static native int crypto_auth_hmacsha512_verify(byte[] hash, byte[] in, byte[] key);

    public static native int crypto_auth_hmacsha512_statebytes();
    public static native int crypto_auth_hmacsha512_init(byte[] state, byte[] key);
    public static native int crypto_auth_hmacsha512_update(byte[] state, byte[] in);
    public static native int crypto_auth_hmacsha512_final(byte[] state, byte[] out);

    //#include "sodium/crypto_box_curve25519xsalsa20poly1305.h"

    public static final int crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
    public static final int crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16;
    public static final int crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
    public static final int crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES + crypto_box_curve25519xsalsa20poly1305_MACBYTES;

    public static native int crypto_box_curve25519xsalsa20poly1305();
    public static native int crypto_box_curve25519xsalsa20poly1305_open();
    public static native int crypto_box_curve25519xsalsa20poly1305_seed_keypair();
    public static native int crypto_box_curve25519xsalsa20poly1305_keypair();
    public static native int crypto_box_curve25519xsalsa20poly1305_beforenm();
    public static native int crypto_box_curve25519xsalsa20poly1305_afternm();
    public static native int crypto_box_curve25519xsalsa20poly1305_open_afternm();

    //#include "sodium/crypto_box.h"

    public static final int crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
    public static final int crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
    public static final int crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
    public static final int crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
    public static final int crypto_box_MACBYTES = crypto_box_curve25519xsalsa20poly1305_MACBYTES;
    public static final String crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305";

    public static native int crypto_box_seed_keypair(byte[] privateKey, byte[] publicKey, byte[] seed);
    public static native int crypto_box_keypair(byte[] privateKey, byte[] publicKey);
    public static native int crypto_box_easy(byte[] ciphertext, byte[] plaintext, byte[] nonce, byte[] receiverPublicKey, byte[] senderPrivateKey);
    public static native int crypto_box_open_easy(byte[] plaintext, byte[] ciphertext, byte[] nonce, byte[] senderPublicKey, byte[] receiverPrivateKey);
    public static native int crypto_box_detached(byte[] ciphertext, byte[] mac, byte[] plaintext, byte[] nonce, byte[] receiverPublicKey, byte[] senderPrivateKey);
    public static native int crypto_box_open_detached(byte[] plaintext, byte[] ciphertext, byte[] mac, byte[] nonce, byte[] senderPublicKey, byte[] receiverPrivateKey);

    /* -- Precomputation interface -- */

    public static final int crypto_box_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;

    public static native int crypto_box_beforenm();
    public static native int crypto_box_easy_afternm();
    public static native int crypto_box_open_easy_afternm();
    public static native int crypto_box_detached_afternm();
    public static native int crypto_box_open_detached_afternm();

    /* -- Ephemeral SK interface -- */

    public static final int crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES;

    public static native int crypto_box_seal();
    public static native int crypto_box_seal_open();

    /* -- NaCl compatibility interface ; Requires padding -- */

    public static final int crypto_box_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
    public static final int crypto_box_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;

    public static native int crypto_box();
    public static native int crypto_box_open();
    public static native int crypto_box_afternm();
    public static native int crypto_box_open_afternm();

    //#include "sodium/crypto_core_hsalsa20.h"

    public static final int crypto_core_hsalsa20_OUTPUTBYTES = 32;
    public static final int crypto_core_hsalsa20_INPUTBYTES = 16;
    public static final int crypto_core_hsalsa20_KEYBYTES = 32;
    public static final int crypto_core_hsalsa20_CONSTBYTES = 16;

    public static native int crypto_core_hsalsa20();

    //#include "sodium/crypto_core_hchacha20.h"

    public static final int crypto_core_hchacha20_OUTPUTBYTES = 32;
    public static final int crypto_core_hchacha20_INPUTBYTES = 16;
    public static final int crypto_core_hchacha20_KEYBYTES = 32;
    public static final int crypto_core_hchacha20_CONSTBYTES = 16;

    public static native int crypto_core_hchacha20();

    //#include "sodium/crypto_core_salsa20.h"

    public static final int crypto_core_salsa20_OUTPUTBYTES = 64;
    public static final int crypto_core_salsa20_INPUTBYTES = 16;
    public static final int crypto_core_salsa20_KEYBYTES = 32;
    public static final int crypto_core_salsa20_CONSTBYTES = 16;

    public static native int crypto_core_salsa20();

    //#include "sodium/crypto_core_salsa2012.h"

    public static final int crypto_core_salsa2012_OUTPUTBYTES = 64;
    public static final int crypto_core_salsa2012_INPUTBYTES = 16;
    public static final int crypto_core_salsa2012_KEYBYTES = 32;
    public static final int crypto_core_salsa2012_CONSTBYTES = 16;

    public static native int crypto_core_salsa2012();

    //#include "sodium/crypto_core_salsa208.h"

    public static final int crypto_core_salsa208_OUTPUTBYTES = 64;
    public static final int crypto_core_salsa208_INPUTBYTES = 16;
    public static final int crypto_core_salsa208_KEYBYTES = 32;
    public static final int crypto_core_salsa208_CONSTBYTES = 16;

    public static native int crypto_core_salsa208();

    //#include "sodium/crypto_generichash_blake2b.h"

    public static final int crypto_generichash_blake2b_BYTES_MIN = 16;
    public static final int crypto_generichash_blake2b_BYTES_MAX = 64;
    public static final int crypto_generichash_blake2b_BYTES = 32;
    public static final int crypto_generichash_blake2b_KEYBYTES_MIN = 16;
    public static final int crypto_generichash_blake2b_KEYBYTES_MAX = 64;
    public static final int crypto_generichash_blake2b_KEYBYTES = 32;
    public static final int crypto_generichash_blake2b_SALTBYTES = 16;
    public static final int crypto_generichash_blake2b_PERSONALBYTES = 16;

    public static native int crypto_generichash_blake2b_statebytes();

    public static native int crypto_generichash_blake2b();
    public static native int crypto_generichash_blake2b_salt_personal();
    public static native int crypto_generichash_blake2b_init();
    public static native int crypto_generichash_blake2b_init_salt_personal();
    public static native int crypto_generichash_blake2b_update();
    public static native int crypto_generichash_blake2b_final();

    //#include "sodium/crypto_generichash.h"

    public static final int crypto_generichash_BYTES_MIN = crypto_generichash_blake2b_BYTES_MIN;
    public static final int crypto_generichash_BYTES_MAX = crypto_generichash_blake2b_BYTES_MAX;
    public static final int crypto_generichash_BYTES = crypto_generichash_blake2b_BYTES;
    public static final int crypto_generichash_KEYBYTES_MIN = crypto_generichash_blake2b_KEYBYTES_MIN;
    public static final int crypto_generichash_KEYBYTES_MAX = crypto_generichash_blake2b_KEYBYTES_MAX;
    public static final int crypto_generichash_KEYBYTES = crypto_generichash_blake2b_KEYBYTES;
    public static final String crypto_generichash_PRIMITIVE = "blake2b";

    public static native int crypto_generichash();
    public static native int crypto_generichash_init();
    public static native int crypto_generichash_update();
    public static native int crypto_generichash_final();




    //#include "sodium/crypto_hash_sha256.h"
    // covered

    public static final int crypto_hash_sha256_BYTES = 32;

    public static native int crypto_hash_sha256(byte[] out, byte[] in, int inOffset, int inLimit);
    public static native int crypto_hash_sha256_statebytes();
    public static native int crypto_hash_sha256_init(byte[] state);
    public static native int crypto_hash_sha256_update(byte[] state, byte[] in, int inOffset, int inLimit);
    public static native int crypto_hash_sha256_final(byte[] state, byte[] out);

    //#include "sodium/crypto_hash_sha512.h"
    // covered

    public static final int crypto_hash_sha512_BYTES = 64;

    public static native int crypto_hash_sha512(byte[] out, byte[] in, int inOffset, int inLimit);
    public static native int crypto_hash_sha512_statebytes();
    public static native int crypto_hash_sha512_init(byte[] state);
    public static native int crypto_hash_sha512_update(byte[] state, byte[] in, int inOffset, int inLimit);
    public static native int crypto_hash_sha512_final(byte[] state, byte[] out);

    //#include "sodium/crypto_hash.h"
    // covered

    public static final int crypto_hash_BYTES = crypto_hash_sha512_BYTES;
    public static final String crypto_hash_PRIMITIVE = "sha512";

    public static native int crypto_hash(byte[] out, byte[] in, int inOffset, int inLimit);

    //#include "sodium/crypto_onetimeauth_poly1305.h"

    public static final int crypto_onetimeauth_poly1305_BYTES = 16;
    public static final int crypto_onetimeauth_poly1305_KEYBYTES = 32;

    public static native int crypto_onetimeauth_poly1305();
    public static native int crypto_onetimeauth_poly1305_verify();
    public static native int crypto_onetimeauth_poly1305_init();
    public static native int crypto_onetimeauth_poly1305_update();
    public static native int crypto_onetimeauth_poly1305_final();

    //#include "sodium/crypto_onetimeauth.h"

    public static final int crypto_onetimeauth_BYTES = crypto_onetimeauth_poly1305_BYTES;
    public static final int crypto_onetimeauth_KEYBYTES = crypto_onetimeauth_poly1305_KEYBYTES;
    public static final String crypto_onetimeauth_PRIMITIVE = "poly1305";

    public static native int crypto_onetimeauth();
    public static native int crypto_onetimeauth_verify();
    public static native int crypto_onetimeauth_init();
    public static native int crypto_onetimeauth_update();
    public static native int crypto_onetimeauth_final();


    //#include "sodium/crypto_pwhash_argon2i.h"

    public static final int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
    public static final int crypto_pwhash_argon2i_SALTBYTES = 16;
    public static final int crypto_pwhash_argon2i_STRBYTES = 128;
    public static final String crypto_pwhash_argon2i_STRPREFIX = "$argon2i$";
    public static final long crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = 4;
    public static final long crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = 33554432;
    public static final long crypto_pwhash_argon2i_OPSLIMIT_MODERATE = 6;
    public static final long crypto_pwhash_argon2i_MEMLIMIT_MODERATE = 134217728;
    public static final long crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = 8;
    public static final long crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = 536870912;

    public static native int crypto_pwhash_argon2i();
    public static native int crypto_pwhash_argon2i_str();
    public static native int crypto_pwhash_argon2i_str_verify();

    //#include "sodium/crypto_pwhash.h"

    public static final int crypto_pwhash_ALG_ARGON2I13 = crypto_pwhash_argon2i_ALG_ARGON2I13;
    public static final int crypto_pwhash_ALG_DEFAULT = crypto_pwhash_ALG_ARGON2I13;
    public static final int crypto_pwhash_SALTBYTES = crypto_pwhash_argon2i_SALTBYTES;
    public static final int crypto_pwhash_STRBYTES = crypto_pwhash_argon2i_STRBYTES;
    public static final String crypto_pwhash_STRPREFIX = crypto_pwhash_argon2i_STRPREFIX;
    public static final long crypto_pwhash_OPSLIMIT_INTERACTIVE = crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE;
    public static final long crypto_pwhash_MEMLIMIT_INTERACTIVE = crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE;
    public static final long crypto_pwhash_OPSLIMIT_MODERATE = crypto_pwhash_argon2i_OPSLIMIT_MODERATE;
    public static final long crypto_pwhash_MEMLIMIT_MODERATE = crypto_pwhash_argon2i_MEMLIMIT_MODERATE;
    public static final long crypto_pwhash_OPSLIMIT_SENSITIVE = crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE;
    public static final long crypto_pwhash_MEMLIMIT_SENSITIVE = crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE;

    public static native int crypto_pwhash();
    public static native int crypto_pwhash_str();
    public static native int crypto_pwhash_str_verify();

    //#include "sodium/crypto_pwhash_scryptsalsa208sha256.h"

    public static final int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
    public static final int crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;
    public static final String crypto_pwhash_scryptsalsa208sha256_STRPREFIX = "$7$";
    public static final long crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;
    public static final long crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;
    public static final long crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = 33554432;
    public static final long crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = 1073741824;

    public static native int crypto_pwhash_scryptsalsa208sha256();
    public static native int crypto_pwhash_scryptsalsa208sha256_str();
    public static native int crypto_pwhash_scryptsalsa208sha256_str_verify();
    public static native int crypto_pwhash_scryptsalsa208sha256_ll();

    //#include "sodium/crypto_scalarmult_curve25519.h"

    public static final int crypto_scalarmult_curve25519_BYTES = 32;
    public static final int crypto_scalarmult_curve25519_SCALARBYTES = 32;

    public static native int crypto_scalarmult_curve25519();
    public static native int crypto_scalarmult_curve25519_base();

    //#include "sodium/crypto_scalarmult.h"

    public static final int crypto_scalarmult_BYTES = crypto_scalarmult_curve25519_BYTES;
    public static final int crypto_scalarmult_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES;
    public static final String crypto_scalarmult_PRIMITIVE = "curve25519";

    public static native int crypto_scalarmult_base();
    public static native int crypto_scalarmult();

    //#include "sodium/crypto_secretbox_xsalsa20poly1305.h"

    public static final int crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
    public static final int crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
    public static final int crypto_secretbox_xsalsa20poly1305_MACBYTES = 16;
    public static final int crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
    public static final int crypto_secretbox_xsalsa20poly1305_ZEROBYTES =
            crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES;

    public static native int crypto_secretbox_xsalsa20poly1305();
    public static native int crypto_secretbox_xsalsa20poly1305_open();

    //#include "sodium/crypto_secretbox.h"

    public static final int crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
    public static final int crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
    public static final int crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES;
    public static final String crypto_secretbox_PRIMITIVE = "xsalsa20poly1305";

    public static native int crypto_secretbox_easy();
    public static native int crypto_secretbox_open_easy();
    public static native int crypto_secretbox_detached();
    public static native int crypto_secretbox_open_detached();

    /* -- NaCl compatibility interface ; Requires padding -- */

    public static final int crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
    public static final int crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

    public static native int crypto_secretbox();
    public static native int crypto_secretbox_open();

    //#include "sodium/crypto_shorthash_siphash24.h"

    public static final int crypto_shorthash_siphash24_BYTES = 8;
    public static final int crypto_shorthash_siphash24_KEYBYTES = 16;

    public static native int crypto_shorthash_siphash24();

    //#include "sodium/crypto_shorthash.h"

    public static final int crypto_shorthash_BYTES = crypto_shorthash_siphash24_BYTES;
    public static final int crypto_shorthash_KEYBYTES = crypto_shorthash_siphash24_KEYBYTES;
    public static final String crypto_shorthash_PRIMITIVE = "siphash24";

    public static native int crypto_shorthash();

    //#include "sodium/crypto_sign_ed25519.h"

    public static final int crypto_sign_ed25519_BYTES = 64;
    public static final int crypto_sign_ed25519_SEEDBYTES = 32;
    public static final int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
    public static final int crypto_sign_ed25519_SECRETKEYBYTES = 32 + 32;

    public static native int crypto_sign_ed25519();
    public static native int crypto_sign_ed25519_open();
    public static native int crypto_sign_ed25519_detached();
    public static native int crypto_sign_ed25519_verify_detached();
    public static native int crypto_sign_ed25519_keypair();
    public static native int crypto_sign_ed25519_seed_keypair();
    public static native int crypto_sign_ed25519_pk_to_curve25519();
    public static native int crypto_sign_ed25519_sk_to_curve25519();
    public static native int crypto_sign_ed25519_sk_to_seed();
    public static native int crypto_sign_ed25519_sk_to_pk();

    //#include "sodium/crypto_sign.h"

    public static final int crypto_sign_BYTES = crypto_sign_ed25519_BYTES;
    public static final int crypto_sign_SEEDBYTES = crypto_sign_ed25519_SEEDBYTES;
    public static final int crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES;
    public static final int crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES;
    public static final String crypto_sign_PRIMITIVE = "ed25519";

    public static native int crypto_sign_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);
    public static native int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);
    public static native int crypto_sign(byte[] signedMessage, byte[] message, byte[] secretKey);
    public static native int crypto_sign_open(byte[] message, byte[] signedMessage, byte[] publicKey);
    public static native int crypto_sign_detached(byte[] signature, byte[] message, byte[] secretkey);
    public static native int crypto_sign_verify_detached(byte[] signature, byte[] message, byte[] publicKey);

    //#include "sodium/crypto_stream_aes128ctr.h"

    public static final int crypto_stream_aes128ctr_KEYBYTES = 16;
    public static final int crypto_stream_aes128ctr_NONCEBYTES = 16;
    public static final int crypto_stream_aes128ctr_BEFORENMBYTES = 1408;

    public static native int crypto_stream_aes128ctr();
    public static native int crypto_stream_aes128ctr_xor();
    public static native int crypto_stream_aes128ctr_beforenm();
    public static native int crypto_stream_aes128ctr_afternm();
    public static native int crypto_stream_aes128ctr_xor_afternm();


    //#include "sodium/crypto_stream_chacha20.h"

    public static final int crypto_stream_chacha20_KEYBYTES = 32;
    public static final int crypto_stream_chacha20_NONCEBYTES = 8;

    public static native int crypto_stream_chacha20();
    public static native int crypto_stream_chacha20_xor();
    public static native int crypto_stream_chacha20_xor_ic();

    /* ChaCha20 with a 96-bit nonce and a 32-bit counter (IETF) */

    public static final int crypto_stream_chacha20_IETF_NONCEBYTES = 12;

    public static native int crypto_stream_chacha20_ietf();
    public static native int crypto_stream_chacha20_ietf_xor();
    public static native int crypto_stream_chacha20_ietf_xor_ic();


    //#include "sodium/crypto_stream_salsa20.h"

    public static final int crypto_stream_salsa20_KEYBYTES = 32;
    public static final int crypto_stream_salsa20_NONCEBYTES = 8;

    public static native int crypto_stream_salsa20();
    public static native int crypto_stream_salsa20_xor();
    public static native int crypto_stream_salsa20_xor_ic();

    //#include "sodium/crypto_stream_salsa2012.h"

    public static final int crypto_stream_salsa2012_KEYBYTES = 32;
    public static final int crypto_stream_salsa2012_NONCEBYTES = 8;

    public static native int crypto_stream_salsa2012();
    public static native int crypto_stream_salsa2012_xor();

    //#include "sodium/crypto_stream_salsa208.h"

    public static final int crypto_stream_salsa208_KEYBYTES = 32;
    public static final int crypto_stream_salsa208_NONCEBYTES = 8;

    public static native int crypto_stream_salsa208();
    public static native int crypto_stream_salsa208_xor();

    //#include "sodium/crypto_stream_xsalsa20.h"

    public static final int crypto_stream_xsalsa20_KEYBYTES = 32;
    public static final int crypto_stream_xsalsa20_NONCEBYTES = 24;

    public static native int crypto_stream_xsalsa20();
    public static native int crypto_stream_xsalsa20_xor();
    public static native int crypto_stream_xsalsa20_xor_ic();

    //#include "sodium/crypto_stream.h"

    public static final int crypto_stream_KEYBYTES = crypto_stream_xsalsa20_KEYBYTES;
    public static final int crypto_stream_NONCEBYTES = crypto_stream_xsalsa20_NONCEBYTES;
    public static final String crypto_stream_PRIMITIVE = "xsalsa20";

    public static native int crypto_stream();
    public static native int crypto_stream_xor();

    //#include "sodium/crypto_verify_16.h"

    public static final int crypto_verify_16_BYTES = 16;

    public static native int crypto_verify_16();

    //#include "sodium/crypto_verify_32.h"

    public static final int crypto_verify_32_BYTES = 32;

    public static native int crypto_verify_32();

    //#include "sodium/crypto_verify_64.h"

    public static final int crypto_verify_64_BYTES = 64;

    public static native int crypto_verify_64();

    //#include "sodium/randombytes.h"
    // coverted

    public static native void randombytes_buf(byte[] buffer);
    public static native int randombytes_random();
    public static native int randombytes_uniform(int upperBound);
    public static native void randombytes_stir();
    public static native int randombytes_close();

    public static native int randombytes_set_implementation();
    public static native String randombytes_implementation_name();

    /* -- NaCl compatibility interface -- */

    public static native void randombytes(byte[] buffer);

    //#include "sodium/randombytes_salsa20_random.h"
    //#include "sodium/randombytes_sysrandom.h"


    //#include "sodium/runtime.h"

    public static native int sodium_runtime_has_neon();
    public static native int sodium_runtime_has_sse2();
    public static native int sodium_runtime_has_sse3();
    public static native int sodium_runtime_has_ssse3();
    public static native int sodium_runtime_has_sse41();
    public static native int sodium_runtime_has_avx();
    public static native int sodium_runtime_has_avx2();
    public static native int sodium_runtime_has_pclmul();
    public static native int sodium_runtime_has_aesni();

    //#include "sodium/utils.h"
    //#include "sodium/version.h"

    public static final String SODIUM_VERSION_STRING = "1.0.11";
    public static final int SODIUM_LIBRARY_VERSION_MAJOR = 9;
    public static final int SODIUM_LIBRARY_VERSION_MINOR = 3;
}
