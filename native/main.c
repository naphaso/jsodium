#include <jni.h>

#include "sodium.h"
#include <stdio.h>

    // GetByteArrayElements
    // GetPrimitiveArrayCritical
    // ReleaseByteArrayElements
    // ReleasePrimitiveArrayCritical
#define GET_BYTES(array) ((unsigned char *) (*env)->GetPrimitiveArrayCritical(env, array, NULL))
#define RELEASE_BYTES(array, data) ((*env)->ReleasePrimitiveArrayCritical(env, array, (jbyte *) data, 0))
#define GET_BYTES_SIZE(array) ((size_t) (*env)->GetArrayLength(env, array))
/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1init(JNIEnv *env, jclass clazz) {
	return sodium_init();	
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_is_available
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1is_1available(JNIEnv *env, jclass clazz) {
	return crypto_aead_aes256gcm_is_available();
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt
 * Signature: ([B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt(JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray message, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
    size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
    unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
    unsigned long long ciphertext_len_result;
    size_t message_len = GET_BYTES_SIZE(message);
    unsigned char *message_bytes = GET_BYTES(message);
    size_t additional_data_len = GET_BYTES_SIZE(additional_data);
    unsigned char *additional_data_bytes = GET_BYTES(additional_data);
    unsigned char *nonce_bytes = GET_BYTES(nonce);
    unsigned char *key_bytes = GET_BYTES(key);

	int result = crypto_aead_aes256gcm_encrypt(ciphertext_bytes, &ciphertext_len_result, message_bytes, message_len, additional_data_bytes, additional_data_len, NULL, nonce_bytes, key_bytes);

    RELEASE_BYTES(ciphertext, ciphertext_bytes);
    RELEASE_BYTES(message, message_bytes);
    RELEASE_BYTES(additional_data, additional_data_bytes);
    RELEASE_BYTES(nonce, nonce_bytes);
    RELEASE_BYTES(key, key_bytes);

    if(result < 0) {
        return result;
    } else {
        return ciphertext_len_result;
    }
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt
 * Signature: ([B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt(JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray ciphertext, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
    size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
    unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
    size_t plaintext_len = GET_BYTES_SIZE(plaintext);
    unsigned long long plaintext_len_result;
    unsigned char *plaintext_bytes = GET_BYTES(plaintext);
    size_t additional_data_len = GET_BYTES_SIZE(additional_data);
    unsigned char *additional_data_bytes = GET_BYTES(additional_data);
    unsigned char *nonce_bytes = GET_BYTES(nonce);
    unsigned char *key_bytes = GET_BYTES(key);

    int result = crypto_aead_aes256gcm_decrypt(plaintext_bytes, &plaintext_len_result, NULL, ciphertext_bytes, ciphertext_len, additional_data_bytes, additional_data_len, nonce_bytes, key_bytes);

    RELEASE_BYTES(ciphertext, ciphertext_bytes);
    RELEASE_BYTES(plaintext, plaintext_bytes);
    RELEASE_BYTES(additional_data, additional_data_bytes);
    RELEASE_BYTES(nonce, nonce_bytes);
    RELEASE_BYTES(key, key_bytes);

    if(result < 0) {
        return result;
    } else {
        return plaintext_len_result;
    }
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1detached(JNIEnv *env, jclass clazz) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1detached(JNIEnv *env, jclass clazz) {
	return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1beforenm(JNIEnv *env, jclass clazz) {
  return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_encrypt_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1encrypt_1detached_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_aes256gcm_decrypt_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1aes256gcm_1decrypt_1detached_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_encrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1encrypt(JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray message, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
        size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
        unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
        unsigned long long ciphertext_len_result;
        size_t message_len = GET_BYTES_SIZE(message);
        unsigned char *message_bytes = GET_BYTES(message);
        size_t additional_data_len = GET_BYTES_SIZE(additional_data);
        unsigned char *additional_data_bytes = GET_BYTES(additional_data);
        unsigned char *nonce_bytes = GET_BYTES(nonce);
        unsigned char *key_bytes = GET_BYTES(key);

    	int result = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext_bytes, &ciphertext_len_result, message_bytes, message_len, additional_data_bytes, additional_data_len, NULL, nonce_bytes, key_bytes);

        RELEASE_BYTES(ciphertext, ciphertext_bytes);
        RELEASE_BYTES(message, message_bytes);
        RELEASE_BYTES(additional_data, additional_data_bytes);
        RELEASE_BYTES(nonce, nonce_bytes);
        RELEASE_BYTES(key, key_bytes);

        if(result < 0) {
            return result;
        } else {
            return ciphertext_len_result;
        }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_decrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1decrypt(JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray ciphertext, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
        size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
        unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
        size_t plaintext_len = GET_BYTES_SIZE(plaintext);
        unsigned long long plaintext_len_result;
        unsigned char *plaintext_bytes = GET_BYTES(plaintext);
        size_t additional_data_len = GET_BYTES_SIZE(additional_data);
        unsigned char *additional_data_bytes = GET_BYTES(additional_data);
        unsigned char *nonce_bytes = GET_BYTES(nonce);
        unsigned char *key_bytes = GET_BYTES(key);

        int result = crypto_aead_chacha20poly1305_ietf_decrypt(plaintext_bytes, &plaintext_len_result, NULL, ciphertext_bytes, ciphertext_len, additional_data_bytes, additional_data_len, nonce_bytes, key_bytes);

        RELEASE_BYTES(ciphertext, ciphertext_bytes);
        RELEASE_BYTES(plaintext, plaintext_bytes);
        RELEASE_BYTES(additional_data, additional_data_bytes);
        RELEASE_BYTES(nonce, nonce_bytes);
        RELEASE_BYTES(key, key_bytes);

        if(result < 0) {
            return result;
        } else {
            return plaintext_len_result;
        }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1encrypt_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_ietf_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1ietf_1decrypt_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_encrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1encrypt(JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray message, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
      size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
      unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
      unsigned long long ciphertext_len_result;
      size_t message_len = GET_BYTES_SIZE(message);
      unsigned char *message_bytes = GET_BYTES(message);
      size_t additional_data_len = GET_BYTES_SIZE(additional_data);
      unsigned char *additional_data_bytes = GET_BYTES(additional_data);
      unsigned char *nonce_bytes = GET_BYTES(nonce);
      unsigned char *key_bytes = GET_BYTES(key);

  	int result = crypto_aead_chacha20poly1305_encrypt(ciphertext_bytes, &ciphertext_len_result, message_bytes, message_len, additional_data_bytes, additional_data_len, NULL, nonce_bytes, key_bytes);

      RELEASE_BYTES(ciphertext, ciphertext_bytes);
      RELEASE_BYTES(message, message_bytes);
      RELEASE_BYTES(additional_data, additional_data_bytes);
      RELEASE_BYTES(nonce, nonce_bytes);
      RELEASE_BYTES(key, key_bytes);

      if(result < 0) {
          return result;
      } else {
          return ciphertext_len_result;
      }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_decrypt
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1decrypt(JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray ciphertext, jbyteArray additional_data, jbyteArray nonce, jbyteArray key) {
      size_t ciphertext_len = GET_BYTES_SIZE(ciphertext);
      unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
      size_t plaintext_len = GET_BYTES_SIZE(plaintext);
      unsigned long long plaintext_len_result;
      unsigned char *plaintext_bytes = GET_BYTES(plaintext);
      size_t additional_data_len = GET_BYTES_SIZE(additional_data);
      unsigned char *additional_data_bytes = GET_BYTES(additional_data);
      unsigned char *nonce_bytes = GET_BYTES(nonce);
      unsigned char *key_bytes = GET_BYTES(key);

      int result = crypto_aead_chacha20poly1305_decrypt(plaintext_bytes, &plaintext_len_result, NULL, ciphertext_bytes, ciphertext_len, additional_data_bytes, additional_data_len, nonce_bytes, key_bytes);

      RELEASE_BYTES(ciphertext, ciphertext_bytes);
      RELEASE_BYTES(plaintext, plaintext_bytes);
      RELEASE_BYTES(additional_data, additional_data_bytes);
      RELEASE_BYTES(nonce, nonce_bytes);
      RELEASE_BYTES(key, key_bytes);

      if(result < 0) {
          return result;
      } else {
          return plaintext_len_result;
      }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_encrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1encrypt_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_aead_chacha20poly1305_decrypt_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1aead_1chacha20poly1305_1decrypt_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jbyteArray key) {
    unsigned char *out_bytes = GET_BYTES(out);
    size_t in_size = GET_BYTES_SIZE(in);
    unsigned char *in_bytes = GET_BYTES(in);
    unsigned char *key_bytes = GET_BYTES(key);

    int result = crypto_auth_hmacsha512256(out_bytes, in_bytes, in_size, key_bytes);

    RELEASE_BYTES(out, out_bytes);
    RELEASE_BYTES(in, in_bytes);
    RELEASE_BYTES(key, key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1verify(JNIEnv *env, jclass clazz, jbyteArray hash, jbyteArray in, jbyteArray key) {
    unsigned char *hash_bytes = GET_BYTES(hash);
    size_t in_size = GET_BYTES_SIZE(in);
    unsigned char *in_bytes = GET_BYTES(in);
    unsigned char *key_bytes = GET_BYTES(key);

    int result = crypto_auth_hmacsha512256_verify(hash_bytes, in_bytes, in_size, key_bytes);

    RELEASE_BYTES(hash, hash_bytes);
    RELEASE_BYTES(in, in_bytes);
    RELEASE_BYTES(key, key_bytes);

    return result;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1statebytes(JNIEnv *env, jclass clazz) {
    return crypto_auth_hmacsha512256_statebytes();
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1init(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray key) {
    unsigned char *state_bytes = GET_BYTES(state);
    size_t key_len = GET_BYTES_SIZE(key);
    unsigned char *key_bytes = GET_BYTES(key);

    int result = crypto_auth_hmacsha512256_init((crypto_auth_hmacsha512256_state *) state_bytes, key_bytes, key_len);

    RELEASE_BYTES(state, state_bytes);
    RELEASE_BYTES(key, key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1update(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray in) {
    unsigned char *state_bytes = GET_BYTES(state);
    size_t in_size = GET_BYTES_SIZE(in);
    unsigned char *in_bytes = GET_BYTES(in);

    int result = crypto_auth_hmacsha512256_update((crypto_auth_hmacsha512256_state *) state_bytes, in_bytes, in_size);

    RELEASE_BYTES(state, state_bytes);
    RELEASE_BYTES(in, in_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512256_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512256_1final(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray out) {
    unsigned char *state_bytes = GET_BYTES(state);
    unsigned char *out_bytes = GET_BYTES(out);

    int result = crypto_auth_hmacsha512256_final((crypto_auth_hmacsha512256_state *) state_bytes, out_bytes);

    RELEASE_BYTES(state, state_bytes);
    RELEASE_BYTES(out, out_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jbyteArray key) {
    unsigned char *out_bytes = GET_BYTES(out);
    size_t in_size = GET_BYTES_SIZE(in);
    unsigned char *in_bytes = GET_BYTES(in);
    unsigned char *key_bytes = GET_BYTES(key);

    int result = crypto_auth(out_bytes, in_bytes, in_size, key_bytes);

    RELEASE_BYTES(in, in_bytes);
    RELEASE_BYTES(out, out_bytes);
    RELEASE_BYTES(key, key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1verify(JNIEnv *env, jclass clazz, jbyteArray hash, jbyteArray in, jbyteArray key) {
  unsigned char *hash_bytes = GET_BYTES(hash);
  size_t in_size = GET_BYTES_SIZE(in);
  unsigned char *in_bytes = GET_BYTES(in);
  unsigned char *key_bytes = GET_BYTES(key);

  int result = crypto_auth_verify(hash_bytes, in_bytes, in_size, key_bytes);

  RELEASE_BYTES(hash, hash_bytes);
  RELEASE_BYTES(in, in_bytes);
  RELEASE_BYTES(key, key_bytes);

  return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jbyteArray key) {
      unsigned char *out_bytes = GET_BYTES(out);
      size_t in_size = GET_BYTES_SIZE(in);
      unsigned char *in_bytes = GET_BYTES(in);
      unsigned char *key_bytes = GET_BYTES(key);

      int result = crypto_auth_hmacsha256(out_bytes, in_bytes, in_size, key_bytes);

      RELEASE_BYTES(out, out_bytes);
      RELEASE_BYTES(in, in_bytes);
      RELEASE_BYTES(key, key_bytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1statebytes(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha256_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha256_1final(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jbyteArray key) {
      unsigned char *out_bytes = GET_BYTES(out);
      size_t in_size = GET_BYTES_SIZE(in);
      unsigned char *in_bytes = GET_BYTES(in);
      unsigned char *key_bytes = GET_BYTES(key);

      int result = crypto_auth_hmacsha512256(out_bytes, in_bytes, in_size, key_bytes);

      RELEASE_BYTES(out, out_bytes);
      RELEASE_BYTES(in, in_bytes);
      RELEASE_BYTES(key, key_bytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1statebytes(JNIEnv *env, jclass clazz) {
    return crypto_auth_hmacsha512_statebytes();
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_auth_hmacsha512_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1auth_1hmacsha512_1final(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1seed_1keypair(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1keypair(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1beforenm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_curve25519xsalsa20poly1305_open_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1curve25519xsalsa20poly1305_1open_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seed_1keypair(JNIEnv *env, jclass clazz, jbyteArray private_key, jbyteArray public_key, jbyteArray seed) {
  unsigned char *private_key_bytes = GET_BYTES(private_key);
  unsigned char *public_key_bytes = GET_BYTES(public_key);
  unsigned char *seed_bytes = GET_BYTES(seed);

  int result = crypto_box_seed_keypair(private_key_bytes, public_key_bytes, seed_bytes);

  RELEASE_BYTES(public_key, public_key_bytes);
  RELEASE_BYTES(private_key, private_key_bytes);
  RELEASE_BYTES(seed, seed_bytes);

  return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1keypair(JNIEnv *env, jclass clazz, jbyteArray private_key, jbyteArray public_key) {
    unsigned char *private_key_bytes = GET_BYTES(private_key);
    unsigned char *public_key_bytes = GET_BYTES(public_key);

    int result = crypto_box_keypair(private_key_bytes, public_key_bytes);

    RELEASE_BYTES(public_key, public_key_bytes);
    RELEASE_BYTES(private_key, private_key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1easy(JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray plaintext, jbyteArray nonce, jbyteArray receiver_public_key, jbyteArray sender_private_key) {
    unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
    size_t plaintext_size = GET_BYTES_SIZE(plaintext);
    unsigned char *plaintext_bytes = GET_BYTES(plaintext);
    unsigned char *nonce_bytes = GET_BYTES(nonce);
    unsigned char *receiver_public_key_bytes = GET_BYTES(receiver_public_key);
    unsigned char *sender_private_key_bytes = GET_BYTES(sender_private_key);

    int result = crypto_box_easy(ciphertext_bytes, plaintext_bytes, plaintext_size, nonce_bytes, receiver_public_key_bytes, sender_private_key_bytes);

    RELEASE_BYTES(ciphertext, ciphertext_bytes);
    RELEASE_BYTES(plaintext, plaintext_bytes);
    RELEASE_BYTES(nonce, nonce_bytes);
    RELEASE_BYTES(receiver_public_key, receiver_public_key_bytes);
    RELEASE_BYTES(sender_private_key, sender_private_key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1easy(JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray ciphertext, jbyteArray nonce, jbyteArray sender_public_key, jbyteArray receiver_private_key) {
      unsigned char *plaintext_bytes = GET_BYTES(plaintext);
      size_t ciphertext_size = GET_BYTES_SIZE(ciphertext);
      unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
      unsigned char *nonce_bytes = GET_BYTES(nonce);
      unsigned char *sender_public_key_bytes = GET_BYTES(sender_public_key);
      unsigned char *receiver_private_key_bytes = GET_BYTES(receiver_private_key);

      int result = crypto_box_open_easy(plaintext_bytes, ciphertext_bytes, ciphertext_size, nonce_bytes, sender_public_key_bytes, receiver_private_key_bytes);

      RELEASE_BYTES(plaintext, plaintext_bytes);
      RELEASE_BYTES(ciphertext, ciphertext_bytes);
      RELEASE_BYTES(nonce, nonce_bytes);
      RELEASE_BYTES(sender_public_key, sender_public_key_bytes);
      RELEASE_BYTES(receiver_private_key, receiver_private_key_bytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1detached(JNIEnv *env, jclass clazz, jbyteArray ciphertext, jbyteArray mac, jbyteArray plaintext, jbyteArray nonce, jbyteArray receiver_public_key, jbyteArray sender_private_key) {
      unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
      unsigned char *mac_bytes = GET_BYTES(mac);
      size_t plaintext_size = GET_BYTES_SIZE(plaintext);
      unsigned char *plaintext_bytes = GET_BYTES(plaintext);
      unsigned char *nonce_bytes = GET_BYTES(nonce);
      unsigned char *receiver_public_key_bytes = GET_BYTES(receiver_public_key);
      unsigned char *sender_private_key_bytes = GET_BYTES(sender_private_key);

      int result = crypto_box_detached(ciphertext_bytes, mac_bytes, plaintext_bytes, plaintext_size, nonce_bytes, receiver_public_key_bytes, sender_private_key_bytes);

      RELEASE_BYTES(ciphertext, ciphertext_bytes);
      RELEASE_BYTES(mac, mac_bytes);
      RELEASE_BYTES(plaintext, plaintext_bytes);
      RELEASE_BYTES(nonce, nonce_bytes);
      RELEASE_BYTES(receiver_public_key, receiver_public_key_bytes);
      RELEASE_BYTES(sender_private_key, sender_private_key_bytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_detached
 * Signature: ()I
 */
 //public static native int crypto_box_open_detached(byte[] plaintext, byte[] ciphertext, byte[] mac, byte[] nonce, byte[] senderPublicKey, byte[] receiverPrivateKey);
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1detached(JNIEnv *env, jclass clazz, jbyteArray plaintext, jbyteArray ciphertext, jbyteArray mac, jbyteArray nonce, jbyteArray sender_public_key, jbyteArray receiver_private_key) {
        unsigned char *plaintext_bytes = GET_BYTES(plaintext);
        size_t ciphertext_size = GET_BYTES_SIZE(ciphertext);
        unsigned char *ciphertext_bytes = GET_BYTES(ciphertext);
        unsigned char *mac_bytes = GET_BYTES(mac);
        unsigned char *nonce_bytes = GET_BYTES(nonce);
        unsigned char *sender_public_key_bytes = GET_BYTES(sender_public_key);
        unsigned char *receiver_private_key_bytes = GET_BYTES(receiver_private_key);

        int result = crypto_box_open_detached(plaintext_bytes, ciphertext_bytes, mac_bytes, ciphertext_size, nonce_bytes, sender_public_key_bytes, receiver_private_key_bytes);

        RELEASE_BYTES(plaintext, plaintext_bytes);
        RELEASE_BYTES(ciphertext, ciphertext_bytes);
        RELEASE_BYTES(mac, mac_bytes);
        RELEASE_BYTES(nonce, nonce_bytes);
        RELEASE_BYTES(sender_public_key, sender_public_key_bytes);
        RELEASE_BYTES(receiver_private_key, receiver_private_key_bytes);

        return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1beforenm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_easy_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1easy_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_easy_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1easy_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1detached_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_detached_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1detached_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seal(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_seal_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1seal_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box(JNIEnv *env, jclass clazz) {
  return 31337;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_box_open_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1box_1open_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_hsalsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1hsalsa20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_hchacha20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1hchacha20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa2012
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa2012(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_core_salsa208
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1core_1salsa208(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1statebytes(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_salt_personal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1salt_1personal(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_init_salt_personal
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1init_1salt_1personal(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_blake2b_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1blake2b_1final(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_generichash_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1generichash_1final(JNIEnv *env, jclass clazz) {
  return 0;
}

/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jint inOffset, jint inLimit) {
    unsigned char *inBytes = GET_BYTES(in);
    unsigned char *outBytes = GET_BYTES(out);

    int result = crypto_hash_sha256(outBytes, inBytes + inOffset, inLimit);

    RELEASE_BYTES(in, inBytes);
    RELEASE_BYTES(out, outBytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1statebytes(JNIEnv *env, jclass clazz) {
  return crypto_hash_sha256_statebytes();
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_init
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1init(JNIEnv *env, jclass clazz, jbyteArray state) {
    unsigned char *stateBytes = GET_BYTES(state);

    int result = crypto_hash_sha256_init((crypto_hash_sha256_state *) stateBytes);

    RELEASE_BYTES(state, stateBytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_update
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1update(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray in, jint inOffset, jint inLimit) {
      unsigned char *stateBytes = GET_BYTES(state);
      unsigned char *inBytes = GET_BYTES(in);

      int result = crypto_hash_sha256_update((crypto_hash_sha256_state *) stateBytes, inBytes + inOffset, inLimit);

      RELEASE_BYTES(state, stateBytes);
      RELEASE_BYTES(in, inBytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha256_final
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha256_1final(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray out) {
  unsigned char *stateBytes = GET_BYTES(state);
  unsigned char *outBytes = GET_BYTES(out);

  int result = crypto_hash_sha256_final((crypto_hash_sha256_state *) stateBytes, outBytes);

  RELEASE_BYTES(state, stateBytes);
  RELEASE_BYTES(out, outBytes);

  return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jint inOffset, jint inLimit) {
      unsigned char *inBytes = GET_BYTES(in);
      unsigned char *outBytes = GET_BYTES(out);

      int result = crypto_hash_sha512(outBytes, inBytes + inOffset, inLimit);

      RELEASE_BYTES(in, inBytes);
      RELEASE_BYTES(out, outBytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_statebytes
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1statebytes(JNIEnv *env, jclass clazz) {
  return crypto_hash_sha512_statebytes();
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_init
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1init(JNIEnv *env, jclass clazz, jbyteArray state) {
      unsigned char *stateBytes = GET_BYTES(state);

      int result = crypto_hash_sha512_init((crypto_hash_sha512_state *) stateBytes);

      RELEASE_BYTES(state, stateBytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_update
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1update(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray in, jint inOffset, jint inLimit) {
        unsigned char *stateBytes = GET_BYTES(state);
        unsigned char *inBytes = GET_BYTES(in);

        int result = crypto_hash_sha512_update((crypto_hash_sha512_state *) stateBytes, inBytes + inOffset, inLimit);

        RELEASE_BYTES(state, stateBytes);
        RELEASE_BYTES(in, inBytes);

        return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash_sha512_final
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash_1sha512_1final(JNIEnv *env, jclass clazz, jbyteArray state, jbyteArray out) {
    unsigned char *stateBytes = GET_BYTES(state);
    unsigned char *outBytes = GET_BYTES(out);

    int result = crypto_hash_sha512_final((crypto_hash_sha512_state *) stateBytes, outBytes);

    RELEASE_BYTES(state, stateBytes);
    RELEASE_BYTES(out, outBytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_hash
 * Signature: ([B[BII)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1hash(JNIEnv *env, jclass clazz, jbyteArray out, jbyteArray in, jint inOffset, jint inLimit) {
      unsigned char *inBytes = GET_BYTES(in);
      unsigned char *outBytes = GET_BYTES(out);

      int result = crypto_hash(outBytes, inBytes + inOffset, inLimit);

      RELEASE_BYTES(in, inBytes);
      RELEASE_BYTES(out, outBytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_poly1305_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1poly1305_1final(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1init(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_update
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1update(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_onetimeauth_final
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1onetimeauth_1final(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i_1str(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_argon2i_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1argon2i_1str_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1str(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1str_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_str
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1str(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_str_verify
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1str_1verify(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_pwhash_scryptsalsa208sha256_ll
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1pwhash_1scryptsalsa208sha256_1ll(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1curve25519(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_curve25519_base
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1curve25519_1base(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult_base
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult_1base(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_scalarmult
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1scalarmult(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_xsalsa20poly1305
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1xsalsa20poly1305(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_xsalsa20poly1305_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1xsalsa20poly1305_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1easy(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open_easy
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open_1easy(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_secretbox_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1secretbox_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_shorthash_siphash24
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1shorthash_1siphash24(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_shorthash
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1shorthash(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1open(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_verify_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1verify_1detached(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1keypair(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1seed_1keypair(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_pk_to_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1pk_1to_1curve25519(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_curve25519
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1curve25519(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_seed
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1seed(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_ed25519_sk_to_pk
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1ed25519_1sk_1to_1pk(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_seed_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1seed_1keypair(JNIEnv *env, jclass clazz, jbyteArray public_key, jbyteArray secret_key, jbyteArray seed) {
    unsigned char *public_key_bytes = GET_BYTES(public_key);
    unsigned char *secret_key_bytes = GET_BYTES(secret_key);
    unsigned char *seed_bytes = GET_BYTES(seed);

    int result = crypto_sign_seed_keypair(public_key_bytes, secret_key_bytes, seed_bytes);

    RELEASE_BYTES(public_key, public_key_bytes);
    RELEASE_BYTES(secret_key, secret_key_bytes);
    RELEASE_BYTES(seed, seed_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_keypair
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1keypair(JNIEnv *env, jclass clazz, jbyteArray public_key, jbyteArray secret_key) {
      unsigned char *public_key_bytes = GET_BYTES(public_key);
      unsigned char *secret_key_bytes = GET_BYTES(secret_key);

      int result = crypto_sign_keypair(public_key_bytes, secret_key_bytes);

      RELEASE_BYTES(public_key, public_key_bytes);
      RELEASE_BYTES(secret_key, secret_key_bytes);

      return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign(JNIEnv *env, jclass clazz, jbyteArray signed_message, jbyteArray message, jbyteArray secret_key) {
    unsigned char *signed_message_bytes = GET_BYTES(signed_message);
    size_t message_len = GET_BYTES_SIZE(message);
    unsigned char *message_bytes = GET_BYTES(message);
    unsigned char *secret_key_bytes = GET_BYTES(secret_key);
    unsigned long long signed_message_result_len;

    int result = crypto_sign(signed_message_bytes, &signed_message_result_len, message_bytes, message_len, secret_key_bytes);

    RELEASE_BYTES(signed_message, signed_message_bytes);
    RELEASE_BYTES(message, message_bytes);
    RELEASE_BYTES(secret_key, secret_key_bytes);

    if(result < 0) {
        return result;
    } else {
        return (int) signed_message_result_len;
    }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_open
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1open(JNIEnv *env, jclass clazz, jbyteArray message, jbyteArray signed_message, jbyteArray public_key) {
    unsigned char *message_bytes = GET_BYTES(message);
    size_t signed_message_len = GET_BYTES_SIZE(signed_message);
    unsigned char *signed_message_bytes = GET_BYTES(signed_message);
    unsigned char *public_key_bytes = GET_BYTES(public_key);
    unsigned long long message_len_result;

    int result = crypto_sign_open(message_bytes, &message_len_result, signed_message_bytes, signed_message_len, public_key_bytes);

    RELEASE_BYTES(message, message_bytes);
    RELEASE_BYTES(signed_message, signed_message_bytes);
    RELEASE_BYTES(public_key, public_key_bytes);

    if(result < 0) {
        return result;
    } else {
        return (int) message_len_result;
    }
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1detached(JNIEnv *env, jclass clazz, jbyteArray signature, jbyteArray message, jbyteArray secret_key) {
    unsigned char *signature_bytes = GET_BYTES(signature);
    size_t message_len = GET_BYTES_SIZE(message);
    unsigned char *message_bytes = GET_BYTES(message);
    unsigned char *secret_key_bytes = GET_BYTES(secret_key);

    int result = crypto_sign_detached(signature_bytes, NULL, message_bytes, message_len, secret_key_bytes);

    RELEASE_BYTES(signature, signature_bytes);
    RELEASE_BYTES(message, message_bytes);
    RELEASE_BYTES(secret_key, secret_key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_sign_verify_detached
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1sign_1verify_1detached(JNIEnv *env, jclass clazz, jbyteArray signature, jbyteArray message, jbyteArray public_key) {
    unsigned char *signature_bytes = GET_BYTES(signature);
    size_t message_len = GET_BYTES_SIZE(message);
    unsigned char *message_bytes = GET_BYTES(message);
    unsigned char *public_key_bytes = GET_BYTES(public_key);

    int result = crypto_sign_verify_detached(signature_bytes, message_bytes, message_len, public_key_bytes);

    RELEASE_BYTES(signature, signature_bytes);
    RELEASE_BYTES(message, message_bytes);
    RELEASE_BYTES(public_key, public_key_bytes);

    return result;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_beforenm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1beforenm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_aes128ctr_xor_afternm
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1aes128ctr_1xor_1afternm(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1xor_1ic(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_chacha20_ietf_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1chacha20_1ietf_1xor_1ic(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa20_1xor_1ic(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa2012
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa2012(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa2012_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa2012_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa208
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa208(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_salsa208_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1salsa208_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xsalsa20_xor_ic
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xsalsa20_1xor_1ic(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_stream_xor
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1stream_1xor(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_16
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_116(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_32
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_132(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    crypto_verify_64
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_crypto_1verify_164(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_buf
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1buf(JNIEnv *env, jclass clazz, jbyteArray buffer) {
  size_t bufferSize = GET_BYTES_SIZE(buffer);
  unsigned char *bufferBytes = GET_BYTES(buffer);
  randombytes_buf(bufferBytes, bufferSize);
  RELEASE_BYTES(buffer, bufferBytes);
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_random
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1random(JNIEnv *env, jclass clazz) {
  return randombytes_random();
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_uniform
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1uniform(JNIEnv *env, jclass clazz, jint upper_bound) {
  return randombytes_uniform(upper_bound);
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_stir
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1stir(JNIEnv *env, jclass clazz) {
  randombytes_stir();
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_close
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1close(JNIEnv *env, jclass clazz) {
  return randombytes_close();
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_set_implementation
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1set_1implementation(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes_implementation_name
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_naphaso_jsodium_Sodium_randombytes_1implementation_1name(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    randombytes
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_naphaso_jsodium_Sodium_randombytes(JNIEnv *env, jclass clazz, jbyteArray b1) {
  return;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_neon
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1neon(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse2
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse2(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse3
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse3(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_ssse3
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1ssse3(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_sse41
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1sse41(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_avx
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1avx(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_avx2
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1avx2(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_pclmul
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1pclmul(JNIEnv *env, jclass clazz) {
  return 0;
}


/*
 * Class:     com_naphaso_jsodium_Sodium
 * Method:    sodium_runtime_has_aesni
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_naphaso_jsodium_Sodium_sodium_1runtime_1has_1aesni(JNIEnv *env, jclass clazz) {
  return 0;
}


