package com.mknotes.app.cloud;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

import com.mknotes.app.NotesApplication;

/**
 * Singleton wrapper around Firebase Authentication (Official SDK).
 * Handles register, login, logout, UID storage.
 * Uses official FirebaseAuth SDK - no manual REST calls, no API key passing.
 * Token refresh is handled automatically by the SDK.
 *
 * SAFETY: All Firebase calls are guarded with try-catch.
 * If Firebase is unavailable (Play Services missing, no internet on first init),
 * methods return safe defaults (not logged in, null UID, etc.) instead of crashing.
 */
public class FirebaseAuthManager {

    private static final String TAG = "FirebaseAuth";
    private static final String PREFS_NAME = "mknotes_firebase";
    private static final String KEY_UID = "firebase_uid";
    private static final String KEY_EMAIL = "firebase_email";

    private static FirebaseAuthManager sInstance;

    /**
     * Lazily-initialized FirebaseAuth reference.
     * Will be null if Firebase is not available on this device.
     */
    private FirebaseAuth firebaseAuth;
    private final SharedPreferences prefs;
    private boolean firebaseInitAttempted = false;

    public static synchronized FirebaseAuthManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new FirebaseAuthManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private FirebaseAuthManager(Context context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        // Lazy init: don't call FirebaseAuth.getInstance() in constructor
        // to avoid crash if Firebase is not available
    }

    /**
     * Get FirebaseAuth instance lazily. Returns null if Firebase is unavailable.
     * This is the ONLY place where FirebaseAuth.getInstance() is called.
     */
    private FirebaseAuth getAuth() {
        if (firebaseAuth != null) {
            return firebaseAuth;
        }
        if (firebaseInitAttempted) {
            // Already tried and failed -- don't retry every call
            return null;
        }
        firebaseInitAttempted = true;
        try {
            if (!NotesApplication.isFirebaseAvailable()) {
                Log.w(TAG, "Firebase not available on this device");
                return null;
            }
            firebaseAuth = FirebaseAuth.getInstance();
            return firebaseAuth;
        } catch (Exception e) {
            Log.e(TAG, "FirebaseAuth.getInstance() failed: " + e.getMessage());
            firebaseAuth = null;
            return null;
        }
    }

    /**
     * Register a new user with email and password.
     * Uses official Firebase Auth SDK - API key is read from google-services.json automatically.
     */
    public void register(final String email, final String password, final AuthCallback callback) {
        FirebaseAuth auth = getAuth();
        if (auth == null) {
            callback.onFailure("Firebase is not available on this device");
            return;
        }
        try {
            auth.createUserWithEmailAndPassword(email, password)
                    .addOnCompleteListener(task -> {
                        if (task.isSuccessful()) {
                            FirebaseUser user = auth.getCurrentUser();
                            if (user != null) {
                                storeUid(user.getUid());
                                storeEmail(email);
                            }
                            callback.onSuccess();
                        } else {
                            String msg = "Registration failed";
                            if (task.getException() != null) {
                                msg = task.getException().getMessage();
                            }
                            Log.e(TAG, "Register failed: " + msg);
                            callback.onFailure(msg);
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Register exception: " + e.getMessage());
            callback.onFailure(e.getMessage());
        }
    }

    /**
     * Login existing user with email and password.
     * Uses official Firebase Auth SDK - API key is read from google-services.json automatically.
     */
    public void login(final String email, final String password, final AuthCallback callback) {
        FirebaseAuth auth = getAuth();
        if (auth == null) {
            callback.onFailure("Firebase is not available on this device");
            return;
        }
        try {
            auth.signInWithEmailAndPassword(email, password)
                    .addOnCompleteListener(task -> {
                        if (task.isSuccessful()) {
                            FirebaseUser user = auth.getCurrentUser();
                            if (user != null) {
                                storeUid(user.getUid());
                                storeEmail(email);
                            }
                            callback.onSuccess();
                        } else {
                            String msg = "Login failed";
                            if (task.getException() != null) {
                                msg = task.getException().getMessage();
                            }
                            Log.e(TAG, "Login failed: " + msg);
                            callback.onFailure(msg);
                        }
                    });
        } catch (Exception e) {
            Log.e(TAG, "Login exception: " + e.getMessage());
            callback.onFailure(e.getMessage());
        }
    }

    /**
     * Logout current user and clear stored credentials.
     */
    public void logout() {
        try {
            FirebaseAuth auth = getAuth();
            if (auth != null) {
                auth.signOut();
            }
        } catch (Exception e) {
            Log.e(TAG, "Logout error: " + e.getMessage());
        }
        prefs.edit()
                .remove(KEY_UID)
                .remove(KEY_EMAIL)
                .apply();
    }

    /**
     * Check if user is currently logged into Firebase.
     * Returns false if Firebase is unavailable (safe default).
     */
    public boolean isLoggedIn() {
        try {
            FirebaseAuth auth = getAuth();
            return auth != null && auth.getCurrentUser() != null;
        } catch (Exception e) {
            Log.e(TAG, "isLoggedIn check failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get the current Firebase user. Returns null if Firebase unavailable.
     */
    public FirebaseUser getCurrentUser() {
        try {
            FirebaseAuth auth = getAuth();
            return auth != null ? auth.getCurrentUser() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get the current user's UID.
     * Returns from Firebase first, falls back to stored UID.
     */
    public String getUid() {
        try {
            FirebaseAuth auth = getAuth();
            if (auth != null) {
                FirebaseUser user = auth.getCurrentUser();
                if (user != null) {
                    return user.getUid();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "getUid error: " + e.getMessage());
        }
        return prefs.getString(KEY_UID, null);
    }

    /**
     * Get stored email address.
     */
    public String getStoredEmail() {
        return prefs.getString(KEY_EMAIL, "");
    }

    /**
     * Store UID locally for quick access.
     */
    private void storeUid(String uid) {
        prefs.edit().putString(KEY_UID, uid).apply();
    }

    /**
     * Store email locally.
     */
    private void storeEmail(String email) {
        prefs.edit().putString(KEY_EMAIL, email).apply();
    }

    /**
     * Callback interface for auth operations.
     */
    public interface AuthCallback {
        void onSuccess();
        void onFailure(String errorMessage);
    }
}
