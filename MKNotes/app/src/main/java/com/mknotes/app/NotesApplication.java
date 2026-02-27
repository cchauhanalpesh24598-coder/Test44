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
 */
public class NotesApplication extends Application {

    private static final String TAG = "NotesApp";

    public static final String CHANNEL_ID_REMINDER = "notes_reminder_channel";
    public static final String CHANNEL_ID_GENERAL = "notes_general_channel";

    public void onCreate() {
        super.onCreate();

        // Allow file:// URIs to be shared with external apps
        StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
        StrictMode.setVmPolicy(builder.build());

        createNotificationChannels();

        // Firebase initializes automatically via google-services.json plugin
        // Initialize Firebase App Check BEFORE any Firestore calls
        initFirebaseAppCheck();

        // Initialize KeyManager singleton
        KeyManager.getInstance(this);

        // Register ProcessLifecycleOwner for auto-lock
        ProcessLifecycleOwner.get().getLifecycle()
                .addObserver(SessionManager.getInstance(this));

        // Auto-delete trash notes older than 30 days on app startup
        try {
            NotesRepository.getInstance(this).cleanupOldTrash();
        } catch (Exception e) {
            // Fail silently - don't block app startup
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
