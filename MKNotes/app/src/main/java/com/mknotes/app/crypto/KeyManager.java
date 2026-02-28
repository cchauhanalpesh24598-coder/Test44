package com.mknotes.app.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.SetOptions;

import com.mknotes.app.NotesApplication;
import com.mknotes.app.cloud.FirebaseAuthManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton manager for the entire vault key lifecycle.
 *
 * Manages:
 * - Vault initialization (first-time setup with DEK generation)
 * - Vault unlock (HMAC-verify + DEK decryption)
 * - Vault lock (DEK zero-fill)
 * - Password change (re-wrap DEK only, no note re-encryption)
 * - Vault metadata sync with Firestore (users/{uid}/vault/crypto_metadata)
 * - Local caching in SharedPreferences
 *
 * Memory safety:
 * - cachedDEK is byte[32], NEVER converted to String
 * - getDEK() returns a COPY of the internal array
 * - lockVault() overwrites cachedDEK with 0x00 via Arrays.fill
 * - Master key byte[] is zeroed immediately after each use
 *
 * Dynamic iterations:
 * - DEFAULT_ITERATIONS (150,000) used ONLY for brand-new vaults
 * - All subsequent derivations read iterations from stored metadata
 * - getIterations() reads from SharedPreferences cache, falls back to Firestore
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // SharedPreferences for vault metadata cache
    private static final String PREFS_NAME = "mknotes_vault";
    private static final String PREF_SALT = "vault_salt";
    private static final String PREF_ENCRYPTED_DEK = "vault_encrypted_dek";
    private static final String PREF_VERIFY_TAG = "vault_verify_tag";
    private static final String PREF_ITERATIONS = "vault_iterations";
    private static final String PREF_KEY_VERSION = "vault_key_version";
    private static final String PREF_VAULT_VERSION = "vault_version";

    // Firestore paths
    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_VAULT = "vault";
    private static final String DOC_CRYPTO_METADATA = "crypto_metadata";

    private static KeyManager sInstance;
    private final SharedPreferences prefs;
    private final Context appContext;

    /**
     * In-memory cached DEK -- the ONLY copy of the unencrypted DEK.
     * NEVER written to disk. Zeroed on lockVault().
     */
    private byte[] cachedDEK;

    public static synchronized KeyManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new KeyManager(context.getApplicationContext());
        }
        return sInstance;
    }

    /** For internal use when Context is already set (e.g., from SessionManager). */
    public static synchronized KeyManager getInstance() {
        return sInstance;
    }

    private KeyManager(Context context) {
        this.appContext = context;
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.cachedDEK = null;
    }

    // ======================== STATE CHECKS ========================

    /**
     * Check if a vault has been initialized (metadata exists locally or in cloud).
     */
    public boolean isVaultInitialized() {
        String salt = prefs.getString(PREF_SALT, null);
        String encDek = prefs.getString(PREF_ENCRYPTED_DEK, null);
        String tag = prefs.getString(PREF_VERIFY_TAG, null);
        return salt != null && salt.length() > 0
                && encDek != null && encDek.length() > 0
                && tag != null && tag.length() > 0;
    }

    /**
     * Check if the vault is currently unlocked (DEK in memory).
     */
    public boolean isVaultUnlocked() {
        return cachedDEK != null;
    }

    /**
     * Get the stored iteration count from local cache.
     * Falls back to DEFAULT_ITERATIONS only when no metadata exists (new vault scenario).
     */
    public int getIterations() {
        return prefs.getInt(PREF_ITERATIONS, CryptoManager.DEFAULT_ITERATIONS);
    }

    /**
     * Get the current vault version (1 = old single-layer, 2 = new 2-layer DEK system).
     */
    public int getVaultVersion() {
        return prefs.getInt(PREF_VAULT_VERSION, 0);
    }

    /**
     * Get the stored salt as hex string.
     */
    public String getSaltHex() {
        return prefs.getString(PREF_SALT, null);
    }

    /**
     * Get the stored encrypted DEK string.
     */
    public String getEncryptedDEK() {
        return prefs.getString(PREF_ENCRYPTED_DEK, null);
    }

    /**
     * Get the stored HMAC verify tag.
     */
    public String getVerifyTag() {
        return prefs.getString(PREF_VERIFY_TAG, null);
    }

    // ======================== DEK ACCESS ========================

    /**
     * Get a COPY of the cached DEK for encryption/decryption operations.
     * Returns null if vault is locked.
     *
     * IMPORTANT: Caller gets a copy, not the internal reference.
     * This prevents accidental mutation and ensures lockVault() fully wipes the DEK.
     */
    public byte[] getDEK() {
        if (cachedDEK == null) {
            return null;
        }
        byte[] copy = new byte[cachedDEK.length];
        System.arraycopy(cachedDEK, 0, copy, 0, cachedDEK.length);
        return copy;
    }

    // ======================== VAULT INITIALIZATION (First-Time) ========================

    /**
     * Initialize a brand-new vault with the given master password.
     *
     * Steps:
     * 1. Generate random 16-byte salt
     * 2. Derive master key via PBKDF2 with DEFAULT_ITERATIONS
     * 3. Generate random 256-bit DEK
     * 4. Encrypt DEK with master key
     * 5. Compute HMAC-SHA256 verify tag
     * 6. Zero-fill master key immediately
     * 7. Store metadata locally + Firestore
     * 8. Cache DEK in memory
     *
     * @param password the master password (min 8 chars, validated by caller)
     * @return true if vault was created successfully
     */
    public boolean initializeVault(String password) {
        if (password == null || password.length() == 0) {
            return false;
        }

        byte[] masterKey = null;
        try {
            // Step 1: Generate salt
            byte[] salt = CryptoManager.generateSalt();
            int iterations = CryptoManager.DEFAULT_ITERATIONS;

            // Step 2: Derive master key
            masterKey = CryptoManager.deriveKey(password, salt, iterations);
            if (masterKey == null) {
                return false;
            }

            // Step 3: Generate DEK
            byte[] dek = CryptoManager.generateDEK();

            // Step 4: Encrypt DEK with master key
            String encryptedDEK = CryptoManager.encryptDEK(dek, masterKey);
            if (encryptedDEK == null) {
                CryptoManager.zeroFill(dek);
                return false;
            }

            // Step 5: Compute HMAC verify tag
            String verifyTag = CryptoManager.computeVerifyTag(masterKey);
            if (verifyTag == null) {
                CryptoManager.zeroFill(dek);
                return false;
            }

            // Step 6: Zero-fill master key immediately
            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            String saltHex = CryptoManager.bytesToHex(salt);

            // Step 7: Store metadata locally
            prefs.edit()
                    .putString(PREF_SALT, saltHex)
                    .putString(PREF_ENCRYPTED_DEK, encryptedDEK)
                    .putString(PREF_VERIFY_TAG, verifyTag)
                    .putInt(PREF_ITERATIONS, iterations)
                    .putInt(PREF_KEY_VERSION, 1)
                    .putInt(PREF_VAULT_VERSION, 2)
                    .commit();

            // Step 7b: Upload to Firestore (async, non-blocking)
            uploadVaultToFirestore();

            // Step 8: Cache DEK in memory
            cachedDEK = dek;

            Log.d(TAG, "Vault initialized successfully with " + iterations + " iterations");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize vault: " + e.getMessage());
            return false;
        } finally {
            // Safety net: ensure master key is zeroed even on exception
            if (masterKey != null) {
                CryptoManager.zeroFill(masterKey);
            }
        }
    }

    // ======================== VAULT UNLOCK ========================

    /**
     * Unlock the vault with the master password.
     *
     * Steps:
     * 1. Load salt and iterations from local metadata
     * 2. Derive master key via PBKDF2 with stored iterations
     * 3. HMAC-verify against stored verify tag (constant-time)
     * 4. If mismatch: zero-fill, return false (no crash)
     * 5. Decrypt encrypted DEK
     * 6. Zero-fill master key immediately
     * 7. Cache DEK in memory
     *
     * @param password the master password
     * @return true if password is correct and vault is now unlocked
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) {
            return false;
        }

        String saltHex = prefs.getString(PREF_SALT, null);
        String encryptedDEK = prefs.getString(PREF_ENCRYPTED_DEK, null);
        String storedTag = prefs.getString(PREF_VERIFY_TAG, null);

        if (saltHex == null || encryptedDEK == null || storedTag == null) {
            Log.w(TAG, "Cannot unlock: vault metadata missing");
            return false;
        }

        byte[] masterKey = null;
        try {
            byte[] salt = CryptoManager.hexToBytes(saltHex);
            int iterations = getIterations();

            // Derive master key
            masterKey = CryptoManager.deriveKey(password, salt, iterations);
            if (masterKey == null) {
                return false;
            }

            // HMAC-verify (constant-time)
            boolean verified = CryptoManager.verifyTag(masterKey, storedTag);
            if (!verified) {
                Log.w(TAG, "HMAC verification failed (wrong password)");
                CryptoManager.zeroFill(masterKey);
                return false;
            }

            // Decrypt DEK
            byte[] dek = CryptoManager.decryptDEK(encryptedDEK, masterKey);

            // Zero-fill master key immediately
            CryptoManager.zeroFill(masterKey);
            masterKey = null;

            if (dek == null) {
                Log.e(TAG, "DEK decryption failed despite HMAC pass");
                return false;
            }

            // Cache DEK
            cachedDEK = dek;

            Log.d(TAG, "Vault unlocked successfully");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Unlock error: " + e.getMessage());
            return false;
        } finally {
            if (masterKey != null) {
                CryptoManager.zeroFill(masterKey);
            }
        }
    }

    // ======================== VAULT LOCK ========================

    /**
     * Lock the vault by zeroing the cached DEK.
     * After this call, getDEK() returns null until unlockVault() is called again.
     */
    public void lockVault() {
        if (cachedDEK != null) {
            Arrays.fill(cachedDEK, (byte) 0);
            cachedDEK = null;
        }
        Log.d(TAG, "Vault locked -- DEK zeroed");
    }

    // ======================== PASSWORD CHANGE ========================

    /**
     * Change the master password. DEK stays the same -- only re-wrapped.
     * Notes are NOT re-encrypted.
     *
     * Steps:
     * 1. Derive old master key with stored iterations, HMAC-verify
     * 2. Decrypt DEK with old master key
     * 3. Zero-fill old master key immediately
     * 4. Generate new salt
     * 5. Derive new master key (use current iterations or optionally bump to DEFAULT)
     * 6. Re-encrypt same DEK with new master key
     * 7. Compute new HMAC verify tag
     * 8. Zero-fill new master key immediately
     * 9. Update metadata locally + Firestore
     *
     * @param oldPassword current master password
     * @param newPassword new master password
     * @param upgradeIterations if true, use DEFAULT_ITERATIONS for the new key
     * @return true if password was changed successfully
     */
    public boolean changePassword(String oldPassword, String newPassword, boolean upgradeIterations) {
        if (oldPassword == null || newPassword == null) {
            return false;
        }

        String saltHex = prefs.getString(PREF_SALT, null);
        String encryptedDEK = prefs.getString(PREF_ENCRYPTED_DEK, null);
        String storedTag = prefs.getString(PREF_VERIFY_TAG, null);

        if (saltHex == null || encryptedDEK == null || storedTag == null) {
            return false;
        }

        byte[] oldMasterKey = null;
        byte[] newMasterKey = null;
        byte[] dek = null;

        try {
            byte[] oldSalt = CryptoManager.hexToBytes(saltHex);
            int currentIterations = getIterations();

            // Step 1: Derive old master key and verify
            oldMasterKey = CryptoManager.deriveKey(oldPassword, oldSalt, currentIterations);
            if (oldMasterKey == null) {
                return false;
            }
            if (!CryptoManager.verifyTag(oldMasterKey, storedTag)) {
                CryptoManager.zeroFill(oldMasterKey);
                return false;
            }

            // Step 2: Decrypt DEK with old master key
            dek = CryptoManager.decryptDEK(encryptedDEK, oldMasterKey);

            // Step 3: Zero-fill old master key
            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            if (dek == null) {
                return false;
            }

            // Step 4: Generate new salt
            byte[] newSalt = CryptoManager.generateSalt();
            int newIterations = upgradeIterations ? CryptoManager.DEFAULT_ITERATIONS : currentIterations;

            // Step 5: Derive new master key
            newMasterKey = CryptoManager.deriveKey(newPassword, newSalt, newIterations);
            if (newMasterKey == null) {
                CryptoManager.zeroFill(dek);
                return false;
            }

            // Step 6: Re-encrypt DEK
            String newEncryptedDEK = CryptoManager.encryptDEK(dek, newMasterKey);
            if (newEncryptedDEK == null) {
                CryptoManager.zeroFill(dek);
                CryptoManager.zeroFill(newMasterKey);
                return false;
            }

            // Step 7: New verify tag
            String newVerifyTag = CryptoManager.computeVerifyTag(newMasterKey);
            if (newVerifyTag == null) {
                CryptoManager.zeroFill(dek);
                CryptoManager.zeroFill(newMasterKey);
                return false;
            }

            // Step 8: Zero-fill new master key
            CryptoManager.zeroFill(newMasterKey);
            newMasterKey = null;

            String newSaltHex = CryptoManager.bytesToHex(newSalt);

            // Step 9: Update metadata
            int keyVersion = prefs.getInt(PREF_KEY_VERSION, 1) + 1;
            prefs.edit()
                    .putString(PREF_SALT, newSaltHex)
                    .putString(PREF_ENCRYPTED_DEK, newEncryptedDEK)
                    .putString(PREF_VERIFY_TAG, newVerifyTag)
                    .putInt(PREF_ITERATIONS, newIterations)
                    .putInt(PREF_KEY_VERSION, keyVersion)
                    .commit();

            // Upload to Firestore
            uploadVaultToFirestore();

            // Update cached DEK (same DEK, just re-wrapped)
            cachedDEK = dek;

            Log.d(TAG, "Password changed successfully (keyVersion=" + keyVersion + ")");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Password change failed: " + e.getMessage());
            return false;
        } finally {
            if (oldMasterKey != null) CryptoManager.zeroFill(oldMasterKey);
            if (newMasterKey != null) CryptoManager.zeroFill(newMasterKey);
            // Note: dek is NOT zeroed here because it becomes cachedDEK on success
        }
    }

    // ======================== FIRESTORE SYNC ========================

    /**
     * Upload vault metadata to Firestore.
     * Path: users/{uid}/vault/crypto_metadata
     * Non-blocking (fire-and-forget with logging).
     */
    public void uploadVaultToFirestore() {
        try {
            if (!NotesApplication.isFirebaseAvailable()) {
                Log.w(TAG, "Cannot upload vault: Firebase not available");
                return;
            }
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
            if (!authManager.isLoggedIn()) {
                Log.w(TAG, "Cannot upload vault: not logged in");
                return;
            }
            String uid = authManager.getUid();
            if (uid == null) {
                return;
            }

            Map<String, Object> data = new HashMap<String, Object>();
            data.put("salt", prefs.getString(PREF_SALT, ""));
            data.put("encryptedDEK", prefs.getString(PREF_ENCRYPTED_DEK, ""));
            data.put("verifyTag", prefs.getString(PREF_VERIFY_TAG, ""));
            data.put("iterations", Integer.valueOf(prefs.getInt(PREF_ITERATIONS, CryptoManager.DEFAULT_ITERATIONS)));
            data.put("keyVersion", Integer.valueOf(prefs.getInt(PREF_KEY_VERSION, 1)));
            data.put("updatedAt", Long.valueOf(System.currentTimeMillis()));

            // Only set createdAt if it is a new document
            FirebaseFirestore.getInstance()
                    .collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_VAULT).document(DOC_CRYPTO_METADATA)
                    .set(data, SetOptions.merge())
                    .addOnSuccessListener(unused -> Log.d(TAG, "Vault metadata uploaded to Firestore"))
                    .addOnFailureListener(e -> Log.e(TAG, "Vault upload failed: " + e.getMessage()));

        } catch (Exception e) {
            Log.e(TAG, "Upload vault exception: " + e.getMessage());
        }
    }

    /**
     * Fetch vault metadata from Firestore and cache locally.
     * Used on reinstall/new device when local SharedPreferences are empty.
     *
     * @param callback result callback (success=true if metadata was found and cached)
     */
    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        try {
            if (!NotesApplication.isFirebaseAvailable()) {
                if (callback != null) callback.onVaultFetched(false);
                return;
            }
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
            if (!authManager.isLoggedIn()) {
                if (callback != null) callback.onVaultFetched(false);
                return;
            }
            String uid = authManager.getUid();
            if (uid == null) {
                if (callback != null) callback.onVaultFetched(false);
                return;
            }

            FirebaseFirestore.getInstance()
                    .collection(COLLECTION_USERS).document(uid)
                    .collection(COLLECTION_VAULT).document(DOC_CRYPTO_METADATA)
                    .get()
                    .addOnSuccessListener(documentSnapshot -> {
                        if (documentSnapshot != null && documentSnapshot.exists()) {
                            Map<String, Object> data = documentSnapshot.getData();
                            if (data != null) {
                                String salt = getStringFromMap(data, "salt");
                                String encDek = getStringFromMap(data, "encryptedDEK");
                                String tag = getStringFromMap(data, "verifyTag");
                                int iterations = getIntFromMap(data, "iterations");
                                int keyVersion = getIntFromMap(data, "keyVersion");

                                if (salt.length() > 0 && encDek.length() > 0 && tag.length() > 0) {
                                    prefs.edit()
                                            .putString(PREF_SALT, salt)
                                            .putString(PREF_ENCRYPTED_DEK, encDek)
                                            .putString(PREF_VERIFY_TAG, tag)
                                            .putInt(PREF_ITERATIONS, iterations > 0 ? iterations : CryptoManager.DEFAULT_ITERATIONS)
                                            .putInt(PREF_KEY_VERSION, keyVersion > 0 ? keyVersion : 1)
                                            .putInt(PREF_VAULT_VERSION, 2)
                                            .commit();
                                    Log.d(TAG, "Vault metadata fetched from Firestore and cached locally");
                                    if (callback != null) callback.onVaultFetched(true);
                                    return;
                                }
                            }
                        }
                        Log.d(TAG, "No vault metadata found in Firestore");
                        if (callback != null) callback.onVaultFetched(false);
                    })
                    .addOnFailureListener(e -> {
                        Log.e(TAG, "Vault fetch failed: " + e.getMessage());
                        if (callback != null) callback.onError(e.getMessage());
                    });

        } catch (Exception e) {
            Log.e(TAG, "Fetch vault exception: " + e.getMessage());
            if (callback != null) callback.onError(e.getMessage());
        }
    }

    // ======================== MIGRATION SUPPORT ========================

    /**
     * Store vault metadata from migration (called by MigrationManager).
     * Does NOT upload to Firestore -- caller handles that.
     */
    public void storeVaultMetadataLocally(String saltHex, String encryptedDEK,
                                          String verifyTag, int iterations) {
        prefs.edit()
                .putString(PREF_SALT, saltHex)
                .putString(PREF_ENCRYPTED_DEK, encryptedDEK)
                .putString(PREF_VERIFY_TAG, verifyTag)
                .putInt(PREF_ITERATIONS, iterations)
                .putInt(PREF_KEY_VERSION, 1)
                .putInt(PREF_VAULT_VERSION, 2)
                .commit();
    }

    /**
     * Set the cached DEK directly (used during migration).
     * Caller must ensure dek is a valid 32-byte array.
     */
    public void setCachedDEK(byte[] dek) {
        this.cachedDEK = dek;
    }

    /**
     * Mark vault version (used after migration completes).
     */
    public void setVaultVersion(int version) {
        prefs.edit().putInt(PREF_VAULT_VERSION, version).commit();
    }

    // ======================== MAP HELPERS ========================

    private static String getStringFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof String) return (String) val;
        return "";
    }

    private static int getIntFromMap(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Integer) return ((Integer) val).intValue();
        if (val instanceof Long) return ((Long) val).intValue();
        if (val instanceof Number) return ((Number) val).intValue();
        return 0;
    }

    // ======================== CALLBACKS ========================

    /**
     * Callback for vault metadata fetch from Firestore.
     * Two methods: onVaultFetched for success (with or without vault data),
     * and onError for network/permission failures.
     */
    public interface VaultFetchCallback {
        void onVaultFetched(boolean vaultFound);
        void onError(String error);
    }
}
