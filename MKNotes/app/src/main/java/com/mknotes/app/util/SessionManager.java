package com.mknotes.app.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.lifecycle.DefaultLifecycleObserver;
import androidx.lifecycle.LifecycleOwner;

import com.mknotes.app.crypto.CryptoManager;
import com.mknotes.app.crypto.KeyManager;

/**
 * Session manager that integrates with the 2-layer DEK encryption system.
 *
 * Responsibilities:
 * - Delegates all vault operations to KeyManager
 * - Implements DefaultLifecycleObserver via ProcessLifecycleOwner for auto-lock
 * - Manages 5-minute background timeout (configurable)
 * - On timeout: calls KeyManager.lockVault() which zeros the DEK byte[]
 * - On foreground return after lock: UI must redirect to MasterPasswordActivity
 * - Meditation playing state suspends timeout
 *
 * Memory safety:
 * - getCachedKey() returns a COPY from KeyManager.getDEK()
 * - No direct key material stored in this class
 * - lockVault() via KeyManager zeros DEK with Arrays.fill
 */
public class SessionManager implements DefaultLifecycleObserver {

    private static final String TAG = "SessionManager";
    private static final String PREFS_NAME = "mknotes_security";
    private static final String KEY_LAST_UNLOCK = "last_unlock_timestamp";
    private static final String KEY_BACKGROUND_TIME = "app_background_timestamp";

    /** Session timeout in milliseconds. 5 minutes by default. */
    public static final long SESSION_TIMEOUT_MS = 5L * 60L * 1000L;

    private SharedPreferences prefs;
    private static SessionManager sInstance;

    /** Handler for scheduling auto-lock after timeout. */
    private final Handler lockHandler = new Handler(Looper.getMainLooper());

    /** Runnable that fires lockVault() after the timeout elapses. */
    private final Runnable lockRunnable = new Runnable() {
        public void run() {
            if (!isMeditationPlaying) {
                Log.d(TAG, "Auto-lock timeout reached -- locking vault");
                lockVault();
            }
        }
    };

    /**
     * Runtime-only flag indicating whether meditation mantra is actively playing.
     * When true, session timeout is temporarily suspended.
     * This flag is NEVER persisted -- it resets to false on app kill/restart.
     */
    private boolean isMeditationPlaying = false;

    public static synchronized SessionManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SessionManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private SessionManager(Context context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // ======================== VAULT DELEGATION ========================

    /**
     * Check if the vault (master password) has been set up.
     * Checks both new system (KeyManager) and old system (SharedPreferences) for compatibility.
     */
    public boolean isPasswordSet() {
        // Check new 2-layer system first
        KeyManager km = KeyManager.getInstance();
        if (km != null && km.isVaultInitialized()) {
            return true;
        }
        // Fallback: check old system
        return prefs.getBoolean("is_master_password_set", false);
    }

    /**
     * Initialize vault with master password (first-time setup).
     * Delegates to KeyManager.initializeVault().
     *
     * @return true if vault was created successfully
     */
    public boolean setMasterPassword(String password) {
        KeyManager km = KeyManager.getInstance();
        if (km == null) return false;

        boolean success = km.initializeVault(password);
        if (success) {
            // Also mark in old prefs for backward compatibility checks
            prefs.edit()
                    .putBoolean("is_master_password_set", true)
                    .putLong(KEY_LAST_UNLOCK, System.currentTimeMillis())
                    .commit();
        }
        return success;
    }

    /**
     * Verify master password and unlock vault.
     * Delegates to KeyManager.unlockVault().
     *
     * @return true if password is correct and vault is now unlocked
     */
    public boolean verifyMasterPassword(String password) {
        KeyManager km = KeyManager.getInstance();
        if (km == null) return false;

        boolean valid = km.unlockVault(password);
        if (valid) {
            prefs.edit().putLong(KEY_LAST_UNLOCK, System.currentTimeMillis()).commit();
        }
        return valid;
    }

    /**
     * Record that the user has successfully unlocked the app right now.
     */
    public void updateSessionTimestamp() {
        prefs.edit().putLong(KEY_LAST_UNLOCK, System.currentTimeMillis()).apply();
    }

    /**
     * Check if vault is unlocked (DEK is in memory).
     */
    public boolean hasKey() {
        KeyManager km = KeyManager.getInstance();
        return km != null && km.isVaultUnlocked();
    }

    /**
     * Get a COPY of the cached DEK for encryption/decryption.
     * Returns null if vault is locked.
     */
    public byte[] getCachedKey() {
        KeyManager km = KeyManager.getInstance();
        if (km == null) return null;
        return km.getDEK();
    }

    /**
     * Check if the current session is still valid.
     * Session is valid if DEK is in memory.
     * If meditation is playing, always return true (no auto-lock during playback).
     */
    public boolean isSessionValid() {
        if (isMeditationPlaying) {
            return true;
        }
        return hasKey();
    }

    // ======================== VAULT LOCK ========================

    /**
     * Lock the vault by zeroing the DEK in KeyManager.
     * Cancels any pending auto-lock timer.
     */
    public void lockVault() {
        KeyManager km = KeyManager.getInstance();
        if (km != null) {
            km.lockVault();
        }
        cancelLockTimer();
        prefs.edit()
                .putLong(KEY_LAST_UNLOCK, 0)
                .remove(KEY_BACKGROUND_TIME)
                .apply();
    }

    /**
     * Force the session to expire immediately.
     * Alias for lockVault() with backward compatibility.
     */
    public void clearSession() {
        lockVault();
    }

    // ======================== LIFECYCLE OBSERVER (Auto-Lock) ========================

    /**
     * Called when app enters foreground.
     * Cancels pending lock timer if app returns before timeout.
     */
    @Override
    public void onStart(LifecycleOwner owner) {
        cancelLockTimer();

        // Check if we were locked while in background
        long bgTime = prefs.getLong(KEY_BACKGROUND_TIME, 0);
        prefs.edit().remove(KEY_BACKGROUND_TIME).apply();

        if (bgTime > 0 && !isMeditationPlaying) {
            long elapsed = System.currentTimeMillis() - bgTime;
            if (elapsed > SESSION_TIMEOUT_MS) {
                // Timeout already expired while in background
                Log.d(TAG, "Background timeout exceeded (" + elapsed + "ms) -- locking vault");
                lockVault();
            }
        }
    }

    /**
     * Called when app goes to background.
     * Starts auto-lock timer.
     */
    @Override
    public void onStop(LifecycleOwner owner) {
        prefs.edit().putLong(KEY_BACKGROUND_TIME, System.currentTimeMillis()).commit();

        if (!isMeditationPlaying && hasKey()) {
            // Schedule lock after timeout
            lockHandler.postDelayed(lockRunnable, SESSION_TIMEOUT_MS);
            Log.d(TAG, "Auto-lock timer started (" + SESSION_TIMEOUT_MS + "ms)");
        }
    }

    /**
     * Cancel the pending auto-lock timer.
     */
    private void cancelLockTimer() {
        lockHandler.removeCallbacks(lockRunnable);
    }

    // ======================== BACKWARD COMPAT (Old System) ========================

    /**
     * Get the stored salt hex from OLD system (mknotes_security prefs).
     * Used during migration and backup export.
     */
    public String getSaltHex() {
        // Try new system first
        KeyManager km = KeyManager.getInstance();
        if (km != null) {
            String salt = km.getSaltHex();
            if (salt != null && salt.length() > 0) return salt;
        }
        // Fallback to old system
        return prefs.getString("master_password_salt", null);
    }

    /**
     * Get the stored verify tag/token.
     * For new system: HMAC tag from KeyManager.
     * For old system: encrypted token from SharedPreferences.
     */
    public String getVerifyToken() {
        KeyManager km = KeyManager.getInstance();
        if (km != null) {
            String tag = km.getVerifyTag();
            if (tag != null && tag.length() > 0) return tag;
        }
        return prefs.getString("master_password_verify_token", null);
    }

    /**
     * Check if old-system encryption migration is done.
     */
    public boolean isEncryptionMigrated() {
        return prefs.getBoolean("encryption_migrated", false);
    }

    /**
     * Mark old-system encryption as migrated.
     */
    public void setEncryptionMigrated(boolean migrated) {
        prefs.edit().putBoolean("encryption_migrated", migrated).commit();
    }

    /**
     * Restore encryption credentials from a backup.
     * For backward compatibility with old backup format.
     */
    public void restoreFromBackup(String saltHex, String verifyToken) {
        prefs.edit()
                .putString("master_password_salt", saltHex)
                .putString("master_password_verify_token", verifyToken)
                .putBoolean("is_master_password_set", true)
                .putBoolean("encryption_migrated", true)
                .commit();
    }

    /**
     * Get stored iteration count from old system.
     */
    public int getStoredIterations() {
        return prefs.getInt("pbkdf2_iterations", 15000);
    }

    // ======================== MEDITATION STATE ========================

    /**
     * Set the meditation playing state.
     * When true, auto-lock timer is suspended.
     */
    public void setMeditationPlaying(boolean playing) {
        isMeditationPlaying = playing;
        if (playing) {
            cancelLockTimer();
        }
    }

    /**
     * Check if meditation mantra is currently playing.
     */
    public boolean isMeditationPlaying() {
        return isMeditationPlaying;
    }

    // ======================== DEPRECATED - Old password change ========================

    /**
     * @deprecated Use PasswordChangeManager instead.
     * Kept for backward compatibility during transition.
     */
    @Deprecated
    public boolean changeMasterPassword(String oldPassword, String newPassword) {
        KeyManager km = KeyManager.getInstance();
        if (km == null) return false;
        return km.changePassword(oldPassword, newPassword, false);
    }

    /**
     * @deprecated Use PasswordChangeManager instead.
     */
    @Deprecated
    public byte[] changeMasterPasswordGetOldKey(String oldPassword, String newPassword) {
        // In the new DEK system, we don't need old key for re-encryption.
        // This method is kept for backward compatibility but just changes the password.
        boolean success = changeMasterPassword(oldPassword, newPassword);
        if (success) {
            // Return the cached DEK (which hasn't changed)
            return getCachedKey();
        }
        return null;
    }

    /**
     * Set the cached derived key directly.
     * @deprecated Only used during old-system migration path.
     */
    @Deprecated
    public void setCachedKey(byte[] key) {
        // In new system, DEK is managed by KeyManager
        // This is a no-op for the new system
    }
}
