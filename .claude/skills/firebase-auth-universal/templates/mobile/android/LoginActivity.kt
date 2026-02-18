/**
 * LoginActivity.kt
 * Android Login Activity with Firebase Authentication
 * Supports email/password and Google Sign In
 */

package com.example.app.ui.auth

import android.content.Intent
import android.os.Bundle
import android.util.Patterns
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.app.R
import com.example.app.auth.AuthManager
import com.example.app.databinding.ActivityLoginBinding
import com.example.app.ui.main.MainActivity
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private lateinit var authManager: AuthManager
    private lateinit var googleSignInClient: GoogleSignInClient

    // Google Sign In launcher
    private val googleSignInLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        try {
            val account = task.getResult(ApiException::class.java)
            account.idToken?.let { idToken ->
                handleGoogleSignIn(idToken)
            } ?: run {
                showError("Failed to get Google credentials")
            }
        } catch (e: ApiException) {
            showError("Google sign in failed: ${e.message}")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Initialize AuthManager
        authManager = AuthManager.getInstance(this)

        // Check if user is already signed in
        if (authManager.isAuthenticated) {
            navigateToMain()
            return
        }

        // Configure Google Sign In
        setupGoogleSignIn()

        // Set up UI listeners
        setupClickListeners()
    }

    // =============================================================================
    // MARK: - Setup
    // =============================================================================

    private fun setupGoogleSignIn() {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(getString(R.string.default_web_client_id))
            .requestEmail()
            .build()

        googleSignInClient = GoogleSignIn.getClient(this, gso)
    }

    private fun setupClickListeners() {
        binding.apply {
            // Email/Password Sign In
            btnSignIn.setOnClickListener {
                handleEmailSignIn()
            }

            // Google Sign In
            btnGoogleSignIn.setOnClickListener {
                launchGoogleSignIn()
            }

            // Forgot Password
            tvForgotPassword.setOnClickListener {
                showResetPasswordDialog()
            }

            // Sign Up
            tvSignUp.setOnClickListener {
                startActivity(Intent(this@LoginActivity, SignUpActivity::class.java))
            }
        }
    }

    // =============================================================================
    // MARK: - Email/Password Sign In
    // =============================================================================

    private fun handleEmailSignIn() {
        val email = binding.etEmail.text.toString().trim()
        val password = binding.etPassword.text.toString()

        // Validate input
        if (!validateInput(email, password)) {
            return
        }

        showLoading(true)

        lifecycleScope.launch {
            val result = authManager.signIn(email, password)

            result.onSuccess {
                showLoading(false)
                navigateToMain()
            }.onFailure { exception ->
                showLoading(false)
                showError(authManager.getErrorMessage(exception as Exception))
            }
        }
    }

    private fun validateInput(email: String, password: String): Boolean {
        return when {
            email.isEmpty() -> {
                binding.tilEmail.error = "Email is required"
                false
            }
            !Patterns.EMAIL_ADDRESS.matcher(email).matches() -> {
                binding.tilEmail.error = "Invalid email address"
                false
            }
            password.isEmpty() -> {
                binding.tilPassword.error = "Password is required"
                false
            }
            else -> {
                binding.tilEmail.error = null
                binding.tilPassword.error = null
                true
            }
        }
    }

    // =============================================================================
    // MARK: - Google Sign In
    // =============================================================================

    private fun launchGoogleSignIn() {
        // Sign out from Google before selecting account
        googleSignInClient.signOut()

        val signInIntent = googleSignInClient.signInIntent
        googleSignInLauncher.launch(signInIntent)
    }

    private fun handleGoogleSignIn(idToken: String) {
        showLoading(true)

        lifecycleScope.launch {
            val result = authManager.signInWithGoogle(idToken)

            result.onSuccess {
                showLoading(false)
                navigateToMain()
            }.onFailure { exception ->
                showLoading(false)
                showError(authManager.getErrorMessage(exception as Exception))
            }
        }
    }

    // =============================================================================
    // MARK: - Password Reset
    // =============================================================================

    private fun showResetPasswordDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_reset_password, null)
        val etResetEmail = dialogView.findViewById<com.google.android.material.textfield.TextInputEditText>(
            R.id.etResetEmail
        )

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Reset Password")
            .setMessage("Enter your email address to receive password reset instructions.")
            .setView(dialogView)
            .setPositiveButton("Send") { _, _ ->
                val email = etResetEmail.text.toString().trim()
                if (email.isNotEmpty() && Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                    sendPasswordResetEmail(email)
                } else {
                    showError("Please enter a valid email address")
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun sendPasswordResetEmail(email: String) {
        showLoading(true)

        lifecycleScope.launch {
            val result = authManager.resetPassword(email)

            result.onSuccess {
                showLoading(false)
                showSuccess("Password reset email sent! Check your inbox.")
            }.onFailure { exception ->
                showLoading(false)
                showError(authManager.getErrorMessage(exception as Exception))
            }
        }
    }

    // =============================================================================
    // MARK: - Navigation
    // =============================================================================

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    // =============================================================================
    // MARK: - UI Helpers
    // =============================================================================

    private fun showLoading(show: Boolean) {
        binding.apply {
            progressBar.visibility = if (show) View.VISIBLE else View.GONE
            btnSignIn.isEnabled = !show
            btnGoogleSignIn.isEnabled = !show
            etEmail.isEnabled = !show
            etPassword.isEnabled = !show
        }
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun showSuccess(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
}

// =============================================================================
// MARK: - Layout XML (activity_login.xml)
// =============================================================================

/*
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:padding="24dp"
    tools:context=".ui.auth.LoginActivity">

    <!-- Logo -->
    <ImageView
        android:id="@+id/ivLogo"
        android:layout_width="100dp"
        android:layout_height="100dp"
        android:src="@drawable/ic_logo"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintBottom_toTopOf="@id/tvTitle"
        app:layout_constraintVertical_chainStyle="packed" />

    <!-- Title -->
    <TextView
        android:id="@+id/tvTitle"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Sign In"
        android:textSize="28sp"
        android:textStyle="bold"
        android:layout_marginTop="16dp"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@id/ivLogo"
        app:layout_constraintBottom_toTopOf="@id/tilEmail" />

    <!-- Email Input -->
    <com.google.android.material.textfield.TextInputLayout
        android:id="@+id/tilEmail"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="32dp"
        android:hint="Email"
        app:layout_constraintTop_toBottomOf="@id/tvTitle"
        app:layout_constraintBottom_toTopOf="@id/tilPassword">

        <com.google.android.material.textfield.TextInputEditText
            android:id="@+id/etEmail"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:inputType="textEmailAddress" />
    </com.google.android.material.textfield.TextInputLayout>

    <!-- Password Input -->
    <com.google.android.material.textfield.TextInputLayout
        android:id="@+id/tilPassword"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="16dp"
        android:hint="Password"
        app:endIconMode="password_toggle"
        app:layout_constraintTop_toBottomOf="@id/tilEmail"
        app:layout_constraintBottom_toTopOf="@id/tvForgotPassword">

        <com.google.android.material.textfield.TextInputEditText
            android:id="@+id/etPassword"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:inputType="textPassword" />
    </com.google.android.material.textfield.TextInputLayout>

    <!-- Forgot Password -->
    <TextView
        android:id="@+id/tvForgotPassword"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Forgot password?"
        android:textColor="@color/primary"
        android:layout_marginTop="8dp"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintTop_toBottomOf="@id/tilPassword"
        app:layout_constraintBottom_toTopOf="@id/btnSignIn" />

    <!-- Sign In Button -->
    <com.google.android.material.button.MaterialButton
        android:id="@+id/btnSignIn"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Sign In"
        android:textSize="16sp"
        android:layout_marginTop="24dp"
        app:layout_constraintTop_toBottomOf="@id/tvForgotPassword"
        app:layout_constraintBottom_toTopOf="@id/tvDivider" />

    <!-- Divider -->
    <TextView
        android:id="@+id/tvDivider"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="OR"
        android:layout_marginTop="24dp"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@id/btnSignIn"
        app:layout_constraintBottom_toTopOf="@id/btnGoogleSignIn" />

    <!-- Google Sign In Button -->
    <com.google.android.material.button.MaterialButton
        android:id="@+id/btnGoogleSignIn"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Continue with Google"
        android:textSize="16sp"
        android:layout_marginTop="24dp"
        app:icon="@drawable/ic_google"
        app:iconGravity="textStart"
        app:iconPadding="8dp"
        style="@style/Widget.Material3.Button.OutlinedButton"
        app:layout_constraintTop_toBottomOf="@id/tvDivider"
        app:layout_constraintBottom_toTopOf="@id/tvSignUp" />

    <!-- Sign Up Link -->
    <TextView
        android:id="@+id/tvSignUp"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Don't have an account? Sign Up"
        android:layout_marginTop="24dp"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@id/btnGoogleSignIn"
        app:layout_constraintBottom_toBottomOf="parent" />

    <!-- Loading Indicator -->
    <ProgressBar
        android:id="@+id/progressBar"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:visibility="gone"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent" />

</androidx.constraintlayout.widget.ConstraintLayout>
*/
