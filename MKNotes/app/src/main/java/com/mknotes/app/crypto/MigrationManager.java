package com.mknotes.app.crypto;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.util.CryptoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

/**
 * Handles migration from old single-layer encryption (master key directly encrypts notes)
 * to the new 2-layer DEK system (master key wraps DEK, DEK encrypts notes).
 *
 * Migration steps:
 * 1. Create full SQLite .db file backup (mknotes.db.pre_migration.bak)
 * 2. Derive old master key from password + old salt (using old iterations)
 * 3. Generate new random DEK (byte[32])
 * 4. Begin SQLite transaction
 * 5. For each note: decrypt with old master key -> re-encrypt with new DEK
 * 6. For each trash note: same decrypt/re-encrypt cycle
 * 7. Commit transaction
 * 8. Zero-fill old master key
 * 9. Generate new salt, derive new master key with DEFAULT_ITERATIONS
 * 10. Encrypt DEK with new master key, compute HMAC verify tag
 * 11. Zero-fill new master key
 * 12. Store vault metadata in Firestore + local SharedPreferences
 * 13. Upload re-encrypted notes to Firestore
 * 14. Set vault_version = 2
 * 15. Delete backup only after full success
 *
 * Failure handling:
 * - SQLite transaction failure: automatic rollback, old data preserved
 * - Post-transaction failure: restore from .pre_migration.bak
 * - Backup file is NEVER deleted until confirmed full success
 */
public class MigrationManager {

    private static final String TAG = "MigrationManager";
    private static final String BACKUP_SUFFIX = ".pre_migration.bak";

    private final Context appContext;

    public MigrationManager(Context context) {
        this.appContext = context.getApplicationContext();
    }

    /**
     * Check if migration from old system to new DEK system is needed.
     * Migration is needed when:
     * - Old encryption data exists (salt in mknotes_security SharedPreferences)
     * - Vault version is 0 or 1 (not yet migrated to 2-layer system)
     */
    public boolean isMigrationNeeded() {
        KeyManager km = KeyManager.getInstance(appContext);
        int vaultVersion = km.getVaultVersion();
        if (vaultVersion >= 2) {
            return false; // Already migrated
        }

        // Check if old system has encryption set up
        android.content.SharedPreferences oldPrefs =
                appContext.getSharedPreferences("mknotes_security", Context.MODE_PRIVATE);
        boolean oldPasswordSet = oldPrefs.getBoolean("is_master_password_set", false);
        String oldSalt = oldPrefs.getString("master_password_salt", null);
        return oldPasswordSet && oldSalt != null && oldSalt.length() > 0;
    }

    /**
     * Perform the full migration from old single-layer encryption to new 2-layer DEK system.
     *
     * @param password the master password (already verified by caller via old system)
     * @return true if migration completed successfully
     */
    public boolean performMigration(String password) {
        if (password == null || password.length() == 0) {
            return false;
        }

        Log.d(TAG, "Starting migration from single-layer to 2-layer DEK encryption");

        byte[] oldMasterKey = null;
        byte[] newDEK = null;
        byte[] newMasterKey = null;

        try {
            // ---- Step 1: Create full SQLite backup ----
            File dbFile = appContext.getDatabasePath("mknotes.db");
            File backupFile = new File(dbFile.getParent(), "mknotes.db" + BACKUP_SUFFIX);

            if (!createFileBackup(dbFile, backupFile)) {
                Log.e(TAG, "Failed to create database backup");
                return false;
            }
            Log.d(TAG, "SQLite backup created: " + backupFile.getAbsolutePath());

            // ---- Step 2: Derive old master key ----
            android.content.SharedPreferences oldPrefs =
                    appContext.getSharedPreferences("mknotes_security", Context.MODE_PRIVATE);
            String oldSaltHex = oldPrefs.getString("master_password_salt", null);
            int oldIterations = oldPrefs.getInt("pbkdf2_iterations", 15000);

            if (oldSaltHex == null) {
                Log.e(TAG, "Old salt not found");
                deleteBackup(backupFile);
                return false;
            }

            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
            oldMasterKey = CryptoUtils.deriveKey(password, oldSalt);
            if (oldMasterKey == null) {
                Log.e(TAG, "Failed to derive old master key");
                deleteBackup(backupFile);
                return false;
            }

            // ---- Step 3: Generate new DEK ----
            newDEK = CryptoManager.generateDEK();

            // ---- Step 4-6: Re-encrypt all notes in transaction ----
            NotesDatabaseHelper dbHelper = NotesDatabaseHelper.getInstance(appContext);
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            boolean transactionSuccess = false;

            db.beginTransaction();
            try {
                // Re-encrypt notes table
                reEncryptTable(db, NotesDatabaseHelper.TABLE_NOTES,
                        new String[]{
                                NotesDatabaseHelper.COL_TITLE,
                                NotesDatabaseHelper.COL_CONTENT,
                                NotesDatabaseHelper.COL_CHECKLIST_DATA,
                                NotesDatabaseHelper.COL_ROUTINE_DATA
                        },
                        NotesDatabaseHelper.COL_ID,
                        oldMasterKey, newDEK);

                // Re-encrypt trash table
                reEncryptTable(db, NotesDatabaseHelper.TABLE_TRASH,
                        new String[]{
                                NotesDatabaseHelper.COL_TRASH_NOTE_TITLE,
                                NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT,
                                NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA
                        },
                        NotesDatabaseHelper.COL_TRASH_ID,
                        oldMasterKey, newDEK);

                db.setTransactionSuccessful();
                transactionSuccess = true;
                Log.d(TAG, "Notes re-encryption transaction committed");
            } catch (Exception e) {
                Log.e(TAG, "Transaction failed, rolling back: " + e.getMessage());
            } finally {
                db.endTransaction();
            }

            if (!transactionSuccess) {
                // Restore from backup
                restoreFromBackup(dbFile, backupFile);
                CryptoManager.zeroFill(oldMasterKey);
                CryptoManager.zeroFill(newDEK);
                return false;
            }

            // ---- Step 8: Zero-fill old master key ----
            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            // ---- Step 9: Generate new salt, derive new master key ----
            byte[] newSalt = CryptoManager.generateSalt();
            int newIterations = CryptoManager.DEFAULT_ITERATIONS;
            newMasterKey = CryptoManager.deriveKey(password, newSalt, newIterations);
            if (newMasterKey == null) {
                Log.e(TAG, "Failed to derive new master key");
                restoreFromBackup(dbFile, backupFile);
                CryptoManager.zeroFill(newDEK);
                return false;
            }

            // ---- Step 10: Encrypt DEK + compute HMAC tag ----
            String encryptedDEK = CryptoManager.encryptDEK(newDEK, newMasterKey);
            String verifyTag = CryptoManager.computeVerifyTag(newMasterKey);

            if (encryptedDEK == null || verifyTag == null) {
                Log.e(TAG, "Failed to create vault metadata");
                restoreFromBackup(dbFile, backupFile);
                CryptoManager.zeroFill(newDEK);
                CryptoManager.zeroFill(newMasterKey);
                return false;
            }

            // ---- Step 11: Zero-fill new master key ----
            CryptoManager.zeroFill(newMasterKey);
            newMasterKey = null;

            String newSaltHex = CryptoManager.bytesToHex(newSalt);

            // ---- Step 12: Store vault metadata ----
            KeyManager km = KeyManager.getInstance(appContext);
            km.storeVaultMetadataLocally(newSaltHex, encryptedDEK, verifyTag, newIterations);
            km.setCachedDEK(newDEK); // Cache the DEK for immediate use

            // Upload to Firestore
            km.uploadVaultToFirestore();

            // ---- Step 13: Upload re-encrypted notes to Firestore ----
            try {
                if (FirebaseAuthManager.getInstance(appContext).isLoggedIn()) {
                    CloudSyncManager.getInstance(appContext).uploadAllNotes();
                }
            } catch (Exception e) {
                // Cloud upload failure is non-fatal; will retry on next sync
                Log.w(TAG, "Cloud upload after migration failed (will retry): " + e.getMessage());
            }

            // ---- Step 14: Set vault_version = 2 ----
            km.setVaultVersion(2);

            // Also mark old encryption as migrated
            oldPrefs.edit().putBoolean("encryption_migrated", true).commit();

            // ---- Step 15: Delete backup after full success ----
            deleteBackup(backupFile);

            Log.d(TAG, "Migration completed successfully");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Migration failed unexpectedly: " + e.getMessage());
            // Try to restore backup
            try {
                File dbFile = appContext.getDatabasePath("mknotes.db");
                File backupFile = new File(dbFile.getParent(), "mknotes.db" + BACKUP_SUFFIX);
                if (backupFile.exists()) {
                    restoreFromBackup(dbFile, backupFile);
                }
            } catch (Exception restoreEx) {
                Log.e(TAG, "Backup restore also failed: " + restoreEx.getMessage());
            }
            return false;
        } finally {
            // Safety net: zero-fill all key material
            if (oldMasterKey != null) CryptoManager.zeroFill(oldMasterKey);
            if (newMasterKey != null) CryptoManager.zeroFill(newMasterKey);
            // newDEK is NOT zeroed because it becomes cachedDEK on success
        }
    }

    // ======================== TABLE RE-ENCRYPTION ========================

    /**
     * Re-encrypt all encrypted columns in a table: decrypt with oldKey, encrypt with newKey.
     * Skips rows where the first encrypted column is not in encrypted format (isEncrypted check).
     */
    private void reEncryptTable(SQLiteDatabase db, String tableName,
                                String[] encryptedColumns, String idColumn,
                                byte[] oldKey, byte[] newKey) {
        Cursor cursor = db.query(tableName, null, null, null, null, null, null);
        if (cursor == null) return;

        try {
            while (cursor.moveToNext()) {
                long id = cursor.getLong(cursor.getColumnIndex(idColumn));
                ContentValues values = new ContentValues();
                boolean hasEncryptedData = false;

                for (String col : encryptedColumns) {
                    int colIdx = cursor.getColumnIndex(col);
                    if (colIdx < 0) continue;

                    String rawValue = cursor.getString(colIdx);
                    if (rawValue == null || rawValue.length() == 0) {
                        values.put(col, "");
                        continue;
                    }

                    // Check if data is encrypted
                    if (CryptoUtils.isEncrypted(rawValue)) {
                        hasEncryptedData = true;
                        // Decrypt with old key
                        String plaintext = CryptoUtils.decrypt(rawValue, oldKey);
                        // Re-encrypt with new DEK
                        String reEncrypted = CryptoManager.encrypt(plaintext, newKey);
                        values.put(col, reEncrypted != null ? reEncrypted : "");
                    } else {
                        // Plaintext data -- encrypt with new DEK
                        String encrypted = CryptoManager.encrypt(rawValue, newKey);
                        values.put(col, encrypted != null ? encrypted : rawValue);
                    }
                }

                if (values.size() > 0) {
                    db.update(tableName, values,
                            idColumn + "=?",
                            new String[]{String.valueOf(id)});
                }
            }
        } finally {
            cursor.close();
        }
    }

    // ======================== FILE BACKUP/RESTORE ========================

    /**
     * Create a file-level copy of the SQLite database.
     */
    private boolean createFileBackup(File source, File dest) {
        if (!source.exists()) return false;
        FileChannel sourceChannel = null;
        FileChannel destChannel = null;
        try {
            sourceChannel = new FileInputStream(source).getChannel();
            destChannel = new FileOutputStream(dest).getChannel();
            destChannel.transferFrom(sourceChannel, 0, sourceChannel.size());
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Backup copy failed: " + e.getMessage());
            return false;
        } finally {
            try { if (sourceChannel != null) sourceChannel.close(); } catch (IOException ignored) {}
            try { if (destChannel != null) destChannel.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Restore database from backup file.
     * Deletes the current db, renames backup to the original db name.
     */
    private void restoreFromBackup(File dbFile, File backupFile) {
        if (!backupFile.exists()) {
            Log.e(TAG, "Backup file does not exist, cannot restore");
            return;
        }
        try {
            // Close any open database connections
            NotesDatabaseHelper.getInstance(appContext).close();

            // Delete corrupted db
            if (dbFile.exists()) {
                dbFile.delete();
            }
            // Rename backup to original
            boolean renamed = backupFile.renameTo(dbFile);
            if (renamed) {
                Log.d(TAG, "Database restored from backup successfully");
            } else {
                // Fallback: copy instead of rename
                createFileBackup(backupFile, dbFile);
                Log.d(TAG, "Database restored from backup via copy");
            }
        } catch (Exception e) {
            Log.e(TAG, "Restore from backup failed: " + e.getMessage());
        }
    }

    /**
     * Delete the backup file.
     */
    private void deleteBackup(File backupFile) {
        if (backupFile != null && backupFile.exists()) {
            boolean deleted = backupFile.delete();
            Log.d(TAG, "Backup file deleted: " + deleted);
        }
    }
}
