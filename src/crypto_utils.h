/*
 * crypto_utils.h — HKDF + AES-256-GCM encryption for eFRAC (C side)
 * ===================================================================
 * Header-only library. Include in delta_agent_c.c and decompress_agent.c.
 * Requires: -lssl -lcrypto (OpenSSL)
 *
 * Wire format:  [12B nonce][ciphertext][16B GCM tag]
 * Must match crypto_utils.py exactly.
 */

#ifndef EFRAC_CRYPTO_UTILS_H
#define EFRAC_CRYPTO_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Constants — must match crypto_utils.py */
#define EFRAC_NONCE_LEN   12
#define EFRAC_TAG_LEN     16
#define EFRAC_OVERHEAD    (EFRAC_NONCE_LEN + EFRAC_TAG_LEN)  /* 28 bytes */
#define EFRAC_KEY_LEN     32  /* AES-256 */

static const unsigned char EFRAC_SALT[] = "efrac-salt-v1";
static const int EFRAC_SALT_LEN = 13;
static const unsigned char EFRAC_INFO[] = "efrac-aes256-gcm-key";
static const int EFRAC_INFO_LEN = 20;

/*
 * Derive AES-256 key from Input Key Material using HKDF-SHA256.
 * out_key must be at least EFRAC_KEY_LEN (32) bytes.
 * Returns 0 on success, -1 on failure.
 */
static int efrac_hkdf_derive(const unsigned char *ikm, int ikm_len,
                             unsigned char *out_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    size_t key_len = EFRAC_KEY_LEN;
    int ret = -1;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, EFRAC_SALT, EFRAC_SALT_LEN) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, ikm_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, EFRAC_INFO, EFRAC_INFO_LEN) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, out_key, &key_len) <= 0) goto cleanup;
    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Read hex-encoded PSK from file and derive AES-256 key.
 * out_key must be at least EFRAC_KEY_LEN (32) bytes.
 * Returns 0 on success, -1 on failure.
 */
static int efrac_derive_key(const char *psk_path, unsigned char *out_key) {
    FILE *fp = fopen(psk_path, "r");
    if (!fp) {
        fprintf(stderr, "[Crypto] Cannot open PSK file: %s\n", psk_path);
        return -1;
    }

    char hex_buf[128];
    memset(hex_buf, 0, sizeof(hex_buf));
    if (!fgets(hex_buf, sizeof(hex_buf), fp)) {
        fclose(fp);
        fprintf(stderr, "[Crypto] Cannot read PSK from %s\n", psk_path);
        return -1;
    }
    fclose(fp);

    /* Strip trailing whitespace */
    int hex_len = strlen(hex_buf);
    while (hex_len > 0 && (hex_buf[hex_len-1] == '\n' || hex_buf[hex_len-1] == '\r'
                          || hex_buf[hex_len-1] == ' '))
        hex_buf[--hex_len] = '\0';

    if (hex_len != 64) {
        fprintf(stderr, "[Crypto] PSK must be 64 hex chars (32 bytes), got %d\n", hex_len);
        return -1;
    }

    /* Hex decode */
    unsigned char ikm[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex_buf + 2*i, "%2x", &byte) != 1) {
            fprintf(stderr, "[Crypto] Invalid hex at position %d\n", 2*i);
            return -1;
        }
        ikm[i] = (unsigned char)byte;
    }

    return efrac_hkdf_derive(ikm, 32, out_key);
}

/*
 * Encrypt plaintext with AES-256-GCM.
 * Output: nonce (12B) + ciphertext (pt_len B) + tag (16B)
 * out must be at least pt_len + EFRAC_OVERHEAD bytes.
 * *out_len is set to the total output length.
 * Returns 0 on success, -1 on failure.
 */
static int efrac_encrypt(const unsigned char *key,
                         const unsigned char *plaintext, int pt_len,
                         unsigned char *out, int *out_len) {
    /* Generate random nonce */
    if (RAND_bytes(out, EFRAC_NONCE_LEN) != 1)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    int ct_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EFRAC_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, out) != 1) goto cleanup;

    /* Encrypt into out + EFRAC_NONCE_LEN */
    if (EVP_EncryptUpdate(ctx, out + EFRAC_NONCE_LEN, &len, plaintext, pt_len) != 1) goto cleanup;
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + EFRAC_NONCE_LEN + ct_len, &len) != 1) goto cleanup;
    ct_len += len;

    /* Append GCM tag after ciphertext */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EFRAC_TAG_LEN,
                            out + EFRAC_NONCE_LEN + ct_len) != 1) goto cleanup;

    *out_len = EFRAC_NONCE_LEN + ct_len + EFRAC_TAG_LEN;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Decrypt an AES-256-GCM blob: nonce (12B) + ciphertext + tag (16B).
 * out must be at least blob_len - EFRAC_OVERHEAD bytes.
 * *out_len is set to the plaintext length.
 * Returns 0 on success (auth OK), -1 on failure (auth fail or error).
 */
static int efrac_decrypt(const unsigned char *key,
                         const unsigned char *blob, int blob_len,
                         unsigned char *out, int *out_len) {
    if (blob_len < EFRAC_OVERHEAD) {
        fprintf(stderr, "[Crypto] Blob too short: %d < %d\n", blob_len, EFRAC_OVERHEAD);
        return -1;
    }

    const unsigned char *nonce = blob;
    const unsigned char *ct = blob + EFRAC_NONCE_LEN;
    int ct_len = blob_len - EFRAC_NONCE_LEN - EFRAC_TAG_LEN;
    const unsigned char *tag = blob + EFRAC_NONCE_LEN + ct_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ret = -1;
    int len = 0;
    int pt_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EFRAC_NONCE_LEN, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;

    if (EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) != 1) goto cleanup;
    pt_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EFRAC_TAG_LEN,
                            (void *)tag) != 1) goto cleanup;

    /* Verify tag + finalize */
    if (EVP_DecryptFinal_ex(ctx, out + pt_len, &len) != 1) {
        fprintf(stderr, "[Crypto] GCM auth tag verification failed!\n");
        goto cleanup;
    }
    pt_len += len;

    *out_len = pt_len;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif /* EFRAC_CRYPTO_UTILS_H */
