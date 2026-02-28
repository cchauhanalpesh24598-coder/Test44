package com.mknotes.app;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.crypto.MigrationManager;
import com.mknotes.app.db.NotesRepository;
import com.mknotes.app.util.PrefsManager;
import com.mknotes.app.util.SessionManager;

/**
 * Gatekeeper activity that requires master password before allowing app access.
 * Two modes: CREATE (first launch) and UNLOCK (subsequent launches after session expiry).
 * This is the LAUNCHER activity -- all app entry goes through here.
 *
 * SAFETY: All external calls (Firebase, KeyManager, Crypto) are wrapped in try-catch.
 * Wrong password returns error message, never crashes.
 * Missing Firebase or network returns safe defaults.
 */
public class MasterPasswordActivity extends AppCompatActivity {
    private static final String TAG = "MasterPassword";
    private static final int MODE_CREATE = 0;
    private static final int MODE_UNLOCK = 1;

    private int currentMode;
    private SessionManager sessionManager;
    private KeyManager keyManager;

    private TextView toolbarTitle;
    private TextView textSubtitle;
    private EditText editPassword;
    private EditText editConfirmPassword;
    private TextView textError;
    private TextView textStrengthHint;
    private Button btnAction;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            sessionManager = SessionManager.getInstance(this);
            keyManager = KeyManager.getInstance(this);

            // If password is set and vault is already unlocked (DEK in memory), skip to main
            if (sessionManager.isPasswordSet() && sessionManager.hasKey()) {
                sessionManager.updateSessionTimestamp();
                launchMain();
                return;
            }
        } catch (Exception e) {
            Log.e(TAG, "Session/KeyManager init error: " + e.getMessage());
            // Continue to show password screen -- user can still create/unlock
            sessionManager = SessionManager.getInstance(this);
            keyManager = KeyManager.getInstance(this);
        }

        setContentView(R.layout.activity_master_password);
        setupStatusBar();
        initViews();

        // Null check views -- if layout fails, finish gracefully
        if (btnAction == null || editPassword == null) {
            Log.e(TAG, "Critical views not found in layout, finishing activity");
            launchMainDirect();
            return;
        }

        try {
            if (sessionManager.isPasswordSet() || keyManager.isVaultInitialized()) {
                setupUnlockMode();
            } else {
                // Check if vault exists in Firestore (reinstall scenario)
                checkForCloudVault();
            }
        } catch (Exception e) {
            Log.e(TAG, "Mode setup error: " + e.getMessage());
            // Default to create mode as safest fallback
            setupCreateMode();
        }
    }

    private void setupStatusBar() {
        try {
            if (Build.VERSION.SDK_INT >= 21) {
                Window window = getWindow();
                window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
                window.setStatusBarColor(getResources().getColor(R.color.colorPrimaryDark));
            }
        } catch (Exception e) {
            Log.e(TAG, "Status bar setup error: " + e.getMessage());
        }
    }

    private void initViews() {
        toolbarTitle = (TextView) findViewById(R.id.toolbar_title);
        textSubtitle = (TextView) findViewById(R.id.text_subtitle);
        editPassword = (EditText) findViewById(R.id.edit_password);
        editConfirmPassword = (EditText) findViewById(R.id.edit_confirm_password);
        textError = (TextView) findViewById(R.id.text_error);
        textStrengthHint = (TextView) findViewById(R.id.text_strength_hint);
        btnAction = (Button) findViewById(R.id.btn_action);
    }

    /**
     * Check if vault metadata exists in Firestore (for reinstall / new device).
     * If Firebase is unavailable or not logged in, skip directly to create mode.
     */
    private void checkForCloudVault() {
        try {
            if (!NotesApplication.isFirebaseAvailable()) {
                setupCreateMode();
                return;
            }

            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);

            if (!authManager.isLoggedIn()) {
                // No Firebase login -- fresh install, show create mode
                setupCreateMode();
                return;
            }

            // Show loading state
            btnAction.setEnabled(false);
            if (textSubtitle != null) {
                textSubtitle.setText("Fetching vault from cloud...");
            }

            keyManager.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
                @Override
                public void onVaultFetched(final boolean vaultExists) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (isFinishing()) return;
                            btnAction.setEnabled(true);
                            if (vaultExists) {
                                setupUnlockMode();
                            } else {
                                setupCreateMode();
                            }
                        }
                    });
                }

                @Override
                public void onError(final String error) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (isFinishing()) return;
                            btnAction.setEnabled(true);
                            if (sessionManager.isPasswordSet()) {
                                setupUnlockMode();
                            } else {
                                setupCreateMode();
                            }
                        }
                    });
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Cloud vault check failed: " + e.getMessage());
            setupCreateMode();
        }
    }

    private void setupCreateMode() {
        currentMode = MODE_CREATE;
        if (toolbarTitle != null) toolbarTitle.setText(R.string.master_password_title_create);
        if (textSubtitle != null) textSubtitle.setText(R.string.master_password_subtitle_create);
        if (editConfirmPassword != null) editConfirmPassword.setVisibility(View.VISIBLE);
        if (textStrengthHint != null) textStrengthHint.setVisibility(View.VISIBLE);
        if (btnAction != null) {
            btnAction.setText(R.string.master_password_btn_create);
            btnAction.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    handleCreate();
                }
            });
        }
        if (textError != null) textError.setVisibility(View.GONE);
    }

    private void setupUnlockMode() {
        currentMode = MODE_UNLOCK;
        if (toolbarTitle != null) toolbarTitle.setText(R.string.master_password_title_unlock);
        if (textSubtitle != null) textSubtitle.setText(R.string.master_password_subtitle_unlock);
        if (editConfirmPassword != null) editConfirmPassword.setVisibility(View.GONE);
        if (textStrengthHint != null) textStrengthHint.setVisibility(View.GONE);
        if (btnAction != null) {
            btnAction.setText(R.string.master_password_btn_unlock);
            btnAction.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    handleUnlock();
                }
            });
        }
        if (textError != null) textError.setVisibility(View.GONE);
    }

    private void handleCreate() {
        try {
            String password = editPassword.getText().toString();
            String confirm = editConfirmPassword != null ? editConfirmPassword.getText().toString() : "";

            // Validate length
            if (password.length() < 8) {
                showError(getString(R.string.master_password_error_short));
                return;
            }

            // Validate match
            if (!password.equals(confirm)) {
                showError(getString(R.string.master_password_error_mismatch));
                return;
            }

            // Disable button to prevent double-tap
            btnAction.setEnabled(false);

            // Initialize vault: generates DEK, encrypts with master key, computes HMAC tag
            boolean success = sessionManager.setMasterPassword(password);
            if (success) {
                // Migrate any existing plaintext notes to encrypted format using DEK
                migrateExistingNotes();

                // Upload vault metadata to Firestore
                uploadVaultToCloud();

                Toast.makeText(this, R.string.master_password_set_success, Toast.LENGTH_SHORT).show();
                launchMain();
            } else {
                btnAction.setEnabled(true);
                showError(getString(R.string.master_password_error_generic));
            }
        } catch (Exception e) {
            Log.e(TAG, "handleCreate error: " + e.getMessage());
            if (btnAction != null) btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_generic));
        }
    }

    private void handleUnlock() {
        try {
            String password = editPassword.getText().toString();

            if (password.length() == 0) {
                showError(getString(R.string.master_password_error_empty));
                return;
            }

            // Disable button to prevent double-tap
            btnAction.setEnabled(false);

            // Check if migration from old system is needed
            int vaultVersion = keyManager.getVaultVersion();

            if (vaultVersion < 2 && isOldSystemPresent()) {
                // Old single-layer system detected -- run migration
                handleMigrationUnlock(password);
            } else {
                // Normal 2-layer DEK unlock
                handleNormalUnlock(password);
            }
        } catch (Exception e) {
            Log.e(TAG, "handleUnlock error: " + e.getMessage());
            if (btnAction != null) btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_wrong));
            if (editPassword != null) editPassword.setText("");
        }
    }

    /**
     * Normal unlock flow using 2-layer DEK system.
     */
    private void handleNormalUnlock(String password) {
        try {
            boolean valid = sessionManager.verifyMasterPassword(password);
            if (valid) {
                sessionManager.updateSessionTimestamp();
                launchMain();
            } else {
                btnAction.setEnabled(true);
                showError(getString(R.string.master_password_error_wrong));
                editPassword.setText("");
            }
        } catch (Exception e) {
            Log.e(TAG, "Normal unlock error: " + e.getMessage());
            if (btnAction != null) btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_wrong));
            if (editPassword != null) editPassword.setText("");
        }
    }

    /**
     * Migration unlock: user's vault is still on old single-layer encryption.
     */
    private void handleMigrationUnlock(final String password) {
        if (textSubtitle != null) textSubtitle.setText("Migrating encryption...");

        new Thread(new Runnable() {
            public void run() {
                try {
                    MigrationManager migrator = new MigrationManager(MasterPasswordActivity.this);
                    boolean success = migrator.performMigration(password);

                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (isFinishing()) return;
                            if (success) {
                                sessionManager.updateSessionTimestamp();
                                uploadVaultToCloud();
                                Toast.makeText(MasterPasswordActivity.this,
                                        "Encryption upgraded successfully",
                                        Toast.LENGTH_SHORT).show();
                                launchMain();
                            } else {
                                btnAction.setEnabled(true);
                                if (textSubtitle != null) {
                                    textSubtitle.setText(R.string.master_password_subtitle_unlock);
                                }
                                showError(getString(R.string.master_password_error_wrong));
                                if (editPassword != null) editPassword.setText("");
                            }
                        }
                    });
                } catch (Exception e) {
                    Log.e(TAG, "Migration error: " + e.getMessage());
                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (isFinishing()) return;
                            if (btnAction != null) btnAction.setEnabled(true);
                            if (textSubtitle != null) {
                                textSubtitle.setText(R.string.master_password_subtitle_unlock);
                            }
                            showError("Migration failed: " + e.getMessage());
                            if (editPassword != null) editPassword.setText("");
                        }
                    });
                }
            }
        }).start();
    }

    /**
     * Check if old single-layer encryption system is present.
     */
    private boolean isOldSystemPresent() {
        try {
            String oldSalt = sessionManager.getSaltHex();
            boolean oldPasswordSet = getSharedPreferences("mknotes_security", MODE_PRIVATE)
                    .getBoolean("is_master_password_set", false);
            return oldSalt != null && oldSalt.length() > 0 && oldPasswordSet;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Migrate existing plaintext notes to encrypted format.
     */
    private void migrateExistingNotes() {
        try {
            byte[] key = sessionManager.getCachedKey();
            if (key == null) {
                return;
            }
            NotesRepository repo = NotesRepository.getInstance(this);
            boolean success = repo.migrateToEncrypted(key);
            if (success) {
                sessionManager.setEncryptionMigrated(true);
            }
        } catch (Exception e) {
            Log.e(TAG, "Note migration failed (will retry): " + e.getMessage());
        }
    }

    /**
     * Upload vault metadata to Firestore for multi-device / reinstall support.
     */
    private void uploadVaultToCloud() {
        try {
            if (!NotesApplication.isFirebaseAvailable()) return;
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
            if (authManager.isLoggedIn()) {
                keyManager.uploadVaultToFirestore();
            }
        } catch (Exception e) {
            Log.e(TAG, "Cloud upload failed (non-fatal): " + e.getMessage());
        }
    }

    private void showError(String message) {
        if (textError != null) {
            textError.setText(message);
            textError.setVisibility(View.VISIBLE);
        }
    }

    private void launchMain() {
        try {
            // Check if Firebase auth is needed for cloud sync
            PrefsManager prefs = PrefsManager.getInstance(this);
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);

            // If user has never logged in to Firebase AND cloud sync is not explicitly disabled,
            // show Firebase login screen on first launch after unlock.
            if (NotesApplication.isFirebaseAvailable()
                    && !authManager.isLoggedIn()
                    && !prefs.isCloudSyncEnabled()
                    && authManager.getUid() == null) {
                Intent intent = new Intent(this, FirebaseLoginActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                startActivity(intent);
                finish();
                return;
            }
        } catch (Exception e) {
            Log.e(TAG, "Firebase login check failed, going to main: " + e.getMessage());
        }

        launchMainDirect();
    }

    /**
     * Directly launch MainActivity without any Firebase checks.
     * Used as ultimate fallback.
     */
    private void launchMainDirect() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    /**
     * Prevent back press from bypassing the password screen.
     */
    public void onBackPressed() {
        moveTaskToBack(true);
    }
}
