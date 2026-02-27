package com.mknotes.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
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
 * New 2-layer encryption flow:
 * - CREATE mode: KeyManager.initializeVault() generates DEK, encrypts with master key,
 *   computes HMAC verifyTag, stores vault metadata in Firestore + local.
 * - UNLOCK mode: KeyManager.unlockVault() derives master key, HMAC-verifies,
 *   decrypts DEK into byte[], caches in memory.
 * - Reinstall flow: Fetches vault metadata from Firestore before prompting password.
 * - Migration: Detects old single-layer encryption and migrates to DEK system.
 */
public class MasterPasswordActivity extends Activity {

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

        sessionManager = SessionManager.getInstance(this);
        keyManager = KeyManager.getInstance(this);

        // If password is set and vault is already unlocked (DEK in memory), skip to main
        if (sessionManager.isPasswordSet() && sessionManager.hasKey()) {
            sessionManager.updateSessionTimestamp();
            launchMain();
            return;
        }

        setContentView(R.layout.activity_master_password);
        setupStatusBar();
        initViews();

        if (sessionManager.isPasswordSet() || keyManager.isVaultInitialized()) {
            setupUnlockMode();
        } else {
            // Check if vault exists in Firestore (reinstall scenario)
            checkForCloudVault();
        }
    }

    private void setupStatusBar() {
        if (Build.VERSION.SDK_INT >= 21) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.setStatusBarColor(getResources().getColor(R.color.colorPrimaryDark));
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
     * If Firebase is logged in, attempt to fetch vault from cloud.
     * If vault found, cache locally and show unlock mode.
     * If no vault or no Firebase, show create mode.
     */
    private void checkForCloudVault() {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);

        if (!authManager.isLoggedIn()) {
            // No Firebase login -- fresh install, show create mode
            setupCreateMode();
            return;
        }

        // Show loading state
        btnAction.setEnabled(false);
        textSubtitle.setText("Fetching vault from cloud...");

        keyManager.fetchVaultFromFirestore(new KeyManager.VaultFetchCallback() {
            @Override
            public void onVaultFetched(final boolean vaultExists) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        btnAction.setEnabled(true);
                        if (vaultExists) {
                            // Vault found in cloud -- show unlock mode
                            setupUnlockMode();
                        } else {
                            // No vault in cloud -- fresh setup
                            setupCreateMode();
                        }
                    }
                });
            }

            @Override
            public void onError(final String error) {
                runOnUiThread(new Runnable() {
                    public void run() {
                        btnAction.setEnabled(true);
                        // Network error -- check if old local vault exists
                        if (sessionManager.isPasswordSet()) {
                            setupUnlockMode();
                        } else {
                            setupCreateMode();
                        }
                    }
                });
            }
        });
    }

    private void setupCreateMode() {
        currentMode = MODE_CREATE;
        toolbarTitle.setText(R.string.master_password_title_create);
        textSubtitle.setText(R.string.master_password_subtitle_create);
        editConfirmPassword.setVisibility(View.VISIBLE);
        textStrengthHint.setVisibility(View.VISIBLE);
        btnAction.setText(R.string.master_password_btn_create);
        textError.setVisibility(View.GONE);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleCreate();
            }
        });
    }

    private void setupUnlockMode() {
        currentMode = MODE_UNLOCK;
        toolbarTitle.setText(R.string.master_password_title_unlock);
        textSubtitle.setText(R.string.master_password_subtitle_unlock);
        editConfirmPassword.setVisibility(View.GONE);
        textStrengthHint.setVisibility(View.GONE);
        btnAction.setText(R.string.master_password_btn_unlock);
        textError.setVisibility(View.GONE);

        btnAction.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                handleUnlock();
            }
        });
    }

    private void handleCreate() {
        String password = editPassword.getText().toString();
        String confirm = editConfirmPassword.getText().toString();

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
    }

    private void handleUnlock() {
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
    }

    /**
     * Normal unlock flow using 2-layer DEK system.
     * KeyManager.unlockVault() derives master key, HMAC-verifies, decrypts DEK.
     */
    private void handleNormalUnlock(String password) {
        boolean valid = sessionManager.verifyMasterPassword(password);
        if (valid) {
            sessionManager.updateSessionTimestamp();
            launchMain();
        } else {
            btnAction.setEnabled(true);
            showError(getString(R.string.master_password_error_wrong));
            editPassword.setText("");
        }
    }

    /**
     * Migration unlock: user's vault is still on old single-layer encryption.
     * Steps:
     * 1. Verify old password using old system (old salt + old iterations)
     * 2. Create full SQLite backup
     * 3. Generate new DEK
     * 4. Re-encrypt all notes: old_key -> plaintext -> DEK
     * 5. Create new vault metadata (new salt, 150k iterations, HMAC tag)
     * 6. Upload to Firestore
     * 7. Mark vault_version = 2
     */
    private void handleMigrationUnlock(final String password) {
        textSubtitle.setText("Migrating encryption...");

        new Thread(new Runnable() {
            public void run() {
                try {
                    MigrationManager migrator = new MigrationManager(MasterPasswordActivity.this);
                    boolean success = migrator.performMigration(password);

                    runOnUiThread(new Runnable() {
                        public void run() {
                            if (success) {
                                sessionManager.updateSessionTimestamp();
                                uploadVaultToCloud();
                                Toast.makeText(MasterPasswordActivity.this,
                                        "Encryption upgraded successfully",
                                        Toast.LENGTH_SHORT).show();
                                launchMain();
                            } else {
                                btnAction.setEnabled(true);
                                textSubtitle.setText(R.string.master_password_subtitle_unlock);
                                showError(getString(R.string.master_password_error_wrong));
                                editPassword.setText("");
                            }
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(new Runnable() {
                        public void run() {
                            btnAction.setEnabled(true);
                            textSubtitle.setText(R.string.master_password_subtitle_unlock);
                            showError("Migration failed: " + e.getMessage());
                            editPassword.setText("");
                        }
                    });
                }
            }
        }).start();
    }

    /**
     * Check if old single-layer encryption system is present.
     * Old system stores salt in mknotes_security SharedPreferences.
     */
    private boolean isOldSystemPresent() {
        String oldSalt = sessionManager.getSaltHex();
        boolean oldPasswordSet = getSharedPreferences("mknotes_security", MODE_PRIVATE)
                .getBoolean("is_master_password_set", false);
        return oldSalt != null && oldSalt.length() > 0 && oldPasswordSet;
    }

    /**
     * Migrate existing plaintext notes to encrypted format.
     * Called once after first vault creation when there might be pre-existing unencrypted data.
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
            // Migration failed -- will retry on next unlock
        }
    }

    /**
     * Upload vault metadata to Firestore for multi-device / reinstall support.
     * Runs asynchronously; failure does not block the user.
     */
    private void uploadVaultToCloud() {
        try {
            FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);
            if (authManager.isLoggedIn()) {
                keyManager.uploadVaultToFirestore();
            }
        } catch (Exception e) {
            // Cloud upload failure must not crash the app
        }
    }

    private void showError(String message) {
        textError.setText(message);
        textError.setVisibility(View.VISIBLE);
    }

    private void launchMain() {
        // Check if Firebase auth is needed for cloud sync
        PrefsManager prefs = PrefsManager.getInstance(this);
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(this);

        // If user has never logged in to Firebase AND cloud sync is not explicitly disabled,
        // show Firebase login screen on first launch after unlock.
        if (!authManager.isLoggedIn() && !prefs.isCloudSyncEnabled()
                && authManager.getUid() == null) {
            Intent intent = new Intent(this, FirebaseLoginActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
            return;
        }

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
