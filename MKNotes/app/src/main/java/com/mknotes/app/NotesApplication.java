package com.mknotes.app;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;
import android.os.StrictMode;
import android.util.Log;

import androidx.lifecycle.ProcessLifecycleOwner;

import com.google.firebase.FirebaseApp;
import com.google.firebase.appcheck.FirebaseAppCheck;
import com.google.firebase.appcheck.debug.DebugAppCheckProviderFactory;
import com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory;

import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.SessionManager;

/**
 * Application class for MKNotes.
 *
 * Initializes:
 * - Firebase (automatic via google-services.json)
 * - Firebase App Check (Debug provider in debug builds, Play Integrity in release)
 * - ProcessLifecycleOwner for auto-lock on background timeout
 * - KeyManager singleton
 * - Notification channels
 * - Auto-cleanup of old trash notes
 *
 * SAFETY: Every initialization step is individually wrapped in try-catch
 * to guarantee that Application.onCreate() NEVER crashes.
 * Any failure is logged and skipped -- the app will still open.
 */
public class NotesApplication extends Application {

    private static final String TAG = "NotesApp";

    public static final String CHANNEL_ID_REMINDER = "notes_reminder_channel";
    public static final String CHANNEL_ID_GENERAL = "notes_general_channel";

    /** Flag indicating whether Firebase initialized successfully. */
    private static boolean sFirebaseAvailable = false;

    /**
     * Check at runtime whether Firebase is available.
     * Other classes should call this before using any Firebase API.
     */
    public static boolean isFirebaseAvailable() {
        return sFirebaseAvailable;
    }

    public void onCreate() {
        super.onCreate();

        // Allow file:// URIs to be shared with external apps
        try {
            StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
            StrictMode.setVmPolicy(builder.build());
        } catch (Exception e) {
            Log.e(TAG, "StrictMode setup failed: " + e.getMessage());
        }

        // Notification channels (safe, no external dependencies)
        try {
            createNotificationChannels();
        } catch (Exception e) {
            Log.e(TAG, "Notification channel creation failed: " + e.getMessage());
        }

        // Firebase initialization -- must happen before App Check
        try {
            FirebaseApp.initializeApp(this);
            sFirebaseAvailable = true;
            Log.d(TAG, "FirebaseApp initialized successfully");
        } catch (Exception e) {
            sFirebaseAvailable = false;
            Log.e(TAG, "FirebaseApp init failed (app continues without Firebase): " + e.getMessage());
        }

        // Firebase App Check (only if Firebase is available)
        if (sFirebaseAvailable) {
            initFirebaseAppCheck();
        }

        // Initialize KeyManager singleton (safe -- only accesses SharedPreferences)
        try {
            KeyManager.getInstance(this);
        } catch (Exception e) {
            Log.e(TAG, "KeyManager init failed: " + e.getMessage());
        }

        // Register ProcessLifecycleOwner for auto-lock
        try {
            ProcessLifecycleOwner.get().getLifecycle()
                    .addObserver(SessionManager.getInstance(this));
        } catch (Exception e) {
            Log.e(TAG, "ProcessLifecycleOwner registration failed: " + e.getMessage());
        }

        // Auto-delete trash notes older than 30 days on app startup
        try {
            NotesRepository.getInstance(this).cleanupOldTrash();
        } catch (Exception e) {
            Log.e(TAG, "Trash cleanup failed (non-fatal): " + e.getMessage());
        }
    }

    /**
     * Initialize Firebase App Check.
     * Debug builds: DebugAppCheckProviderFactory (works on emulators and test devices)
     * Release builds: PlayIntegrityAppCheckProviderFactory (Google Play Integrity API)
     */
    private void initFirebaseAppCheck() {
        try {
            FirebaseApp app = FirebaseApp.getInstance();
            FirebaseAppCheck firebaseAppCheck = FirebaseAppCheck.getInstance(app);

            if (BuildConfig.DEBUG) {
                firebaseAppCheck.installAppCheckProviderFactory(
                        DebugAppCheckProviderFactory.getInstance()
                );
                Log.d(TAG, "Firebase App Check: Debug provider installed");
            } else {
                firebaseAppCheck.installAppCheckProviderFactory(
                        PlayIntegrityAppCheckProviderFactory.getInstance()
                );
                Log.d(TAG, "Firebase App Check: Play Integrity provider installed");
            }
        } catch (Exception e) {
            Log.e(TAG, "Firebase App Check init failed: " + e.getMessage());
            // Non-fatal: app continues without App Check enforcement
        }
    }

    private void createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel reminderChannel = new NotificationChannel(
                    CHANNEL_ID_REMINDER,
                    "Note Reminders",
                    NotificationManager.IMPORTANCE_HIGH
            );
            reminderChannel.setDescription("Notifications for note reminders");
            reminderChannel.enableVibration(true);

            NotificationChannel generalChannel = new NotificationChannel(
                    CHANNEL_ID_GENERAL,
                    "General",
                    NotificationManager.IMPORTANCE_DEFAULT
            );
            generalChannel.setDescription("General notifications");

            NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (manager != null) {
                manager.createNotificationChannel(reminderChannel);
                manager.createNotificationChannel(generalChannel);
            }
        }
    }
}
