package com.mknotes.app.crypto;

import android.content.Context;
import android.util.Log;

import com.mknotes.app.cloud.CloudSyncManager;
import com.mknotes.app.cloud.FirebaseAuthManager;

/**
 * Handles the secure password change flow for the 2-layer DEK system.
 *
 * With the DEK architecture, password change ONLY re-wraps the DEK with a new KEK.
 * Notes are NOT re-encrypted because they use the DEK (which stays the same).
 *
 * Flow:
 * 1. Verify old password (HMAC-SHA256 check)
 * 2. Decrypt DEK with old master key
 * 3. Zero-fill old master key
 * 4. Generate new salt
 * 5. Derive new master key with iterations (same or upgraded to DEFAULT)
 * 6. Re-encrypt same DEK with new master key
 * 7. Compute new HMAC verify tag
 * 8. Zero-fill new master key
 * 9. Update metadata in SharedPreferences + Firestore
 * 10. Upload vault metadata to Firestore so other devices can re-fetch
 */
public class PasswordChangeManager {

    private static final String TAG = "PasswordChange";

    private final Context appContext;

    public PasswordChangeManager(Context context) {
        this.appContext = context.getApplicationContext();
    }

    /**
     * Change the master password.
     * DEK stays the same -- only the wrapping KEK changes.
     * Notes are NOT re-encrypted.
     *
     * @param oldPassword   current master password
     * @param newPassword   new master password (min 8 chars, validated by caller)
     * @return true if password was changed successfully
     */
    public boolean changePassword(String oldPassword, String newPassword) {
        if (oldPassword == null || newPassword == null
                || oldPassword.length() == 0 || newPassword.length() == 0) {
            return false;
        }

        KeyManager km = KeyManager.getInstance(appContext);

        // Delegate to KeyManager which handles the full re-wrap flow
        boolean success = km.changePassword(oldPassword, newPassword, false);

        if (success) {
            Log.d(TAG, "Password changed successfully");

            // Upload updated vault metadata to Firestore
            try {
                km.uploadVaultToFirestore();
            } catch (Exception e) {
                Log.w(TAG, "Vault upload after password change failed (will retry): " + e.getMessage());
            }
        } else {
            Log.e(TAG, "Password change failed");
        }

        return success;
    }

    /**
     * Change password with optional iteration count upgrade.
     * If upgradeIterations is true, the new KEK will use DEFAULT_ITERATIONS
     * instead of the current stored iteration count.
     *
     * @param oldPassword       current master password
     * @param newPassword       new master password
     * @param upgradeIterations if true, bump iterations to DEFAULT_ITERATIONS
     * @return true if successful
     */
    public boolean changePasswordWithUpgrade(String oldPassword, String newPassword,
                                             boolean upgradeIterations) {
        if (oldPassword == null || newPassword == null
                || oldPassword.length() == 0 || newPassword.length() == 0) {
            return false;
        }

        KeyManager km = KeyManager.getInstance(appContext);
        boolean success = km.changePassword(oldPassword, newPassword, upgradeIterations);

        if (success) {
            Log.d(TAG, "Password changed with iteration upgrade=" + upgradeIterations);
            try {
                km.uploadVaultToFirestore();
            } catch (Exception e) {
                Log.w(TAG, "Vault upload failed: " + e.getMessage());
            }
        }

        return success;
    }
}
