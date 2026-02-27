package com.mknotes.app.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PRO-LEVEL 2-LAYER CRYPTO ENGINE for MKNotes.
 *
 * Security model:
 * - PBKDF2WithHmacSHA256 with DYNAMIC iterations (read from metadata, never hardcoded at call-sites)
 * - DEFAULT_ITERATIONS (150,000) used ONLY when creating a brand-new vault
 * - AES-256-GCM with random 12-byte IV per encryption call, 128-bit auth tag
 * - HMAC-SHA256 based password verification (NOT encrypted plaintext)
 * - 2-layer key hierarchy: Master Password -> KEK -> DEK -> Notes
 * - DEK always byte[32], never String
 * - All intermediate key material zero-filled immediately after use
 * - No Base64 encoding of key material in memory -- hex only at storage boundary
 *
 * Thread-safe: all methods are static and stateless.
 */
public final class CryptoManager {

    /** Default iterations for NEW vault creation only. Existing vaults read from metadata. */
    public static final int DEFAULT_ITERATIONS = 150_000;

    private static final int SALT_LENGTH = 16;
    private static final int DEK_LENGTH = 32; // 256 bits
    private static final int KEY_LENGTH_BITS = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits

    /** Constant used for HMAC-based vault verification. */
    private static final String VERIFY_CONSTANT = "MKNOTES_VAULT_VERIFY";

    private static final SecureRandom sRandom = new SecureRandom();

    private CryptoManager() {
        // Utility class - no instances
    }

    // ======================== KEY DERIVATION ========================

    /**
     * Derive a 256-bit master key from password + salt using PBKDF2WithHmacSHA256.
     * Iterations is ALWAYS passed as parameter -- never read from a constant internally.
     *
     * @param password   the master password
     * @param salt       16-byte salt
     * @param iterations PBKDF2 iteration count (read from stored metadata)
     * @return derived key as byte[32], or null on failure
     */
    public static byte[] deriveKey(String password, byte[] salt, int iterations) {
        if (password == null || salt == null || iterations <= 0) {
            return null;
        }
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    iterations,
                    KEY_LENGTH_BITS
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    // ======================== SALT & DEK GENERATION ========================

    /**
     * Generate a cryptographically random 16-byte salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        sRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a cryptographically random 256-bit DEK (Data Encryption Key).
     *
     * @return random byte[32]
     */
    public static byte[] generateDEK() {
        byte[] dek = new byte[DEK_LENGTH];
        sRandom.nextBytes(dek);
        return dek;
    }

    // ======================== DEK ENCRYPTION/DECRYPTION ========================

    /**
     * Encrypt DEK with master key (KEK) using AES-256-GCM.
     * Returns hex string in format: ivHex:ciphertextHex
     * This is the ONLY place where key material is serialized to string (storage boundary).
     *
     * @param dek       the 32-byte DEK to encrypt
     * @param masterKey the 32-byte KEK derived from password
     * @return encrypted DEK as "ivHex:ciphertextHex", or null on failure
     */
    public static String encryptDEK(byte[] dek, byte[] masterKey) {
        if (dek == null || masterKey == null) {
            return null;
        }
        try {
            byte[] iv = generateIV();
            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(dek);
            return bytesToHex(iv) + ":" + bytesToHex(ciphertext);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt encrypted DEK with master key (KEK) using AES-256-GCM.
     *
     * @param encryptedDEK the "ivHex:ciphertextHex" string
     * @param masterKey    the 32-byte KEK derived from password
     * @return decrypted DEK as byte[32], or null on failure (wrong key, corrupted data)
     */
    public static byte[] decryptDEK(String encryptedDEK, byte[] masterKey) {
        if (encryptedDEK == null || masterKey == null) {
            return null;
        }
        try {
            int colonIdx = encryptedDEK.indexOf(':');
            if (colonIdx <= 0) {
                return null;
            }
            String ivHex = encryptedDEK.substring(0, colonIdx);
            String cipherHex = encryptedDEK.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                return null;
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // AEADBadTagException (wrong key) or any other failure
            return null;
        }
    }

    // ======================== NOTE ENCRYPTION/DECRYPTION (using DEK) ========================

    /**
     * Encrypt plaintext note field using DEK and AES-256-GCM.
     * Returns hex string in format: ivHex:ciphertextHex
     *
     * @param plaintext the text to encrypt
     * @param dek       the 32-byte DEK
     * @return encrypted string, empty string for null/empty input, or null on failure
     */
    public static String encrypt(String plaintext, byte[] dek) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (dek == null) {
            return null;
        }
        try {
            byte[] iv = generateIV();
            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return bytesToHex(iv) + ":" + bytesToHex(ciphertext);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt ciphertext note field using DEK and AES-256-GCM.
     * Input format: ivHex:ciphertextHex
     *
     * @param encryptedData the encrypted string
     * @param dek           the 32-byte DEK
     * @return decrypted plaintext, empty string for null/empty input, original on format mismatch
     */
    public static String decrypt(String encryptedData, byte[] dek) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (dek == null) {
            return null;
        }
        try {
            int colonIdx = encryptedData.indexOf(':');
            if (colonIdx <= 0) {
                // Not encrypted data, return as-is (migration support)
                return encryptedData;
            }
            String ivHex = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) {
                // Not encrypted data, return as-is
                return encryptedData;
            }

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            // Decryption failed -- could be unencrypted legacy data or wrong key
            return encryptedData;
        }
    }

    // ======================== HMAC-SHA256 VERIFICATION ========================

    /**
     * Compute HMAC-SHA256 verification tag for the master key.
     * Used to verify the password is correct WITHOUT decrypting any ciphertext.
     *
     * @param masterKey the 32-byte derived master key
     * @return hex-encoded HMAC tag string, or null on failure
     */
    public static String computeVerifyTag(byte[] masterKey) {
        if (masterKey == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(masterKey, "HmacSHA256");
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(VERIFY_CONSTANT.getBytes("UTF-8"));
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Verify master key against a stored HMAC verification tag.
     * Uses constant-time comparison via MessageDigest.isEqual to prevent timing attacks.
     *
     * @param masterKey the 32-byte derived master key to verify
     * @param storedTag the hex-encoded HMAC tag from storage
     * @return true if the key produces a matching HMAC tag
     */
    public static boolean verifyTag(byte[] masterKey, String storedTag) {
        if (masterKey == null || storedTag == null || storedTag.length() == 0) {
            return false;
        }
        try {
            String computedTag = computeVerifyTag(masterKey);
            if (computedTag == null) {
                return false;
            }
            // Constant-time comparison
            byte[] computedBytes = hexToBytes(computedTag);
            byte[] storedBytes = hexToBytes(storedTag);
            return MessageDigest.isEqual(computedBytes, storedBytes);
        } catch (Exception e) {
            return false;
        }
    }

    // ======================== MEMORY SAFETY ========================

    /**
     * Zero-fill a byte array to wipe key material from memory.
     * Safe to call with null.
     */
    public static void zeroFill(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    // ======================== UTILITY ========================

    /**
     * Generate a random 12-byte IV for AES-GCM.
     */
    private static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        sRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Check if a string looks like encrypted data (ivHex:ciphertextHex format).
     */
    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) {
            return false;
        }
        int colonIdx = data.indexOf(':');
        if (colonIdx != GCM_IV_LENGTH * 2) {
            return false;
        }
        String ivPart = data.substring(0, colonIdx);
        for (int i = 0; i < ivPart.length(); i++) {
            char c = ivPart.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Convert byte array to lowercase hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * Convert hex string to byte array.
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() == 0) return new byte[0];
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
