#include <jni.h>

#include "sodium.h"
/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1init(JNIEnv *, jclass) {
	return sodium_init();	
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_is_available
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1is_1available(JNIEnv *, jclass) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt
 * Signature: ([B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt(JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt
 * Signature: ([B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt(JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1detached(JNIEnv *, jclass) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1detached(JNIEnv *, jclass) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1beforenm(JNIEnv *, jclass) {

}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1detached_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1detached_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_encrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1encrypt
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_decrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1decrypt
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1encrypt_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1decrypt_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_encrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1encrypt
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_decrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1decrypt
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1encrypt_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1decrypt_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1statebytes
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1seed_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1beforenm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_open_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1open_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seed_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1easy
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1easy
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1beforenm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_easy_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1easy_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_easy_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1easy_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1detached_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1detached_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seal
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seal_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seal_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_hsalsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1hsalsa20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_hchacha20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1hchacha20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa2012
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa2012
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa208
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa208
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1statebytes
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_salt_personal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1salt_1personal
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_init_salt_personal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1init_1salt_1personal
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1statebytes
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_init
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1init
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_update
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1update
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_final
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1final
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1statebytes
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_init
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1init
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_update
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1update
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_final
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1final
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1init
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1update
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1final
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i_1str
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i_1str_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1str
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1str_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1str
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1str_1verify
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_ll
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1ll
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1curve25519
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_curve25519_base
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1curve25519_1base
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_base
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1base
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_xsalsa20poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1xsalsa20poly1305
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_xsalsa20poly1305_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1xsalsa20poly1305_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1easy
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open_1easy
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_shorthash_siphash24
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1shorthash_1siphash24
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_shorthash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1shorthash
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_verify_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1verify_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1seed_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_pk_to_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1pk_1to_1curve25519
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1curve25519
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_seed
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1seed
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_pk
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1pk
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1seed_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1keypair
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1open
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_verify_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1verify_1detached
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1beforenm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_xor_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1xor_1afternm
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1xor_1ic
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf_1xor_1ic
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20_1xor_1ic
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa2012
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa2012
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa2012_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa2012_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa208
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa208
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa208_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa208_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20_1xor_1ic
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xor
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_16
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_116
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_32
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_132
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_64
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_164
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_buf
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1buf
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_random
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1random
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_uniform
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1uniform
  (JNIEnv *, jclass, jint);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_stir
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1stir
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_close
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1close
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_set_implementation
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1set_1implementation
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_implementation_name
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1implementation_1name
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_neon
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1neon
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse2
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse2
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse3
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse3
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_ssse3
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1ssse3
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse41
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse41
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_avx
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1avx
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_avx2
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1avx2
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_pclmul
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1pclmul
  (JNIEnv *, jclass);

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_aesni
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1aesni
  (JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif
