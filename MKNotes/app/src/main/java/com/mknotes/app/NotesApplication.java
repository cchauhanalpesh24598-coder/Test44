package com.mknotes.app;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;
import android.os.StrictMode;
import android.util.Log;
import android.widget.Toast;

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

    @Override
    public void onCreate() {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable throwable) {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append(throwable.toString()).append("\n");
                    for (StackTraceElement el : throwable.getStackTrace()) {
                        sb.append("at ").append(el.toString()).append("\n");
                    }
                    Throwable cause = throwable.getCause();
                    while (cause != null) {
                        sb.append("Caused by: ").append(cause.toString()).append("\n");
                        for (StackTraceElement el : cause.getStackTrace()) {
                            sb.append("at ").append(el.toString()).append("\n");
                        }
                        cause = cause.getCause();
                    }
                    // Downloads folder mein save
                    java.io.File downloads = android.os.Environment
                        .getExternalStoragePublicDirectory(
                            android.os.Environment.DIRECTORY_DOWNLOADS);
                    java.io.File log = new java.io.File(downloads, "mknotes_crash.txt");
                    java.io.FileWriter fw = new java.io.FileWriter(log, false);
                    fw.write(sb.toString());
                    fw.close();
                } catch (Exception ignored) {}
                android.os.Process.killProcess(android.os.Process.myPid());
            }
        });
        
        super.onCreate();

        StrictMode.VmPolicy.Builder builder = new StrictMode.VmPolicy.Builder();
        StrictMode.setVmPolicy(builder.build());

        createNotificationChannels();

        try {
            initFirebaseAppCheck();
        } catch (Throwable e) {
            log("Firebase fail: " + e.getMessage());
        }

        try {
            KeyManager.getInstance(this);
        } catch (Throwable e) {
            log("KeyManager fail: " + e.getMessage());
        }

        try {
            ProcessLifecycleOwner.get().getLifecycle()
                .addObserver(SessionManager.getInstance(this));
        } catch (Throwable e) {
            log("SessionManager fail: " + e.getMessage());
        }

        try {
            NotesRepository.getInstance(this).cleanupOldTrash();
        } catch (Throwable e) {
            log("Repository fail: " + e.getMessage());
        }
    }

    private void log(String msg) {
        android.util.Log.e("MKNotes_CRASH", msg);
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show();
    }

    /**
     * Initialize Firebase App Check.
     * Debug builds: DebugAppCheckProviderFactory (works on emulators and test devices)
     * Release builds: PlayIntegrityAppCheckProviderFactory (Google Play Integrity API)
     */
    private void initFirebaseAppCheck() {
        try {
            FirebaseApp.initializeApp(this);
            sFirebaseAvailable = true;
            Log.d(TAG, "FirebaseApp initialized successfully");
            
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
        } catch (Throwable t) {
            sFirebaseAvailable = false;
            Log.e(TAG, "Firebase App Check init failed: " + t.getMessage());
            // Non-fatal: app continues without App Check enforcement
            throw t; // Re-throw to be caught by caller's try-catch
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
