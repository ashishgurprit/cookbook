/**
 * AuthManager.kt
 * Firebase Authentication Manager for Android (Kotlin)
 * Complete production-ready implementation with all auth methods
 */

package com.example.app.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.firebase.FirebaseException
import com.google.firebase.auth.*
import com.google.firebase.auth.ktx.auth
import com.google.firebase.ktx.Firebase
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.tasks.await
import java.util.concurrent.TimeUnit

/**
 * Singleton AuthManager for Firebase Authentication
 */
class AuthManager private constructor(private val context: Context) {

    companion object {
        @Volatile
        private var instance: AuthManager? = null

        fun getInstance(context: Context): AuthManager {
            return instance ?: synchronized(this) {
                instance ?: AuthManager(context.applicationContext).also { instance = it }
            }
        }
    }

    // Firebase Auth instance
    private val auth: FirebaseAuth = Firebase.auth

    // Encrypted SharedPreferences for secure token storage
    private val encryptedPrefs: SharedPreferences by lazy {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

        EncryptedSharedPreferences.create(
            "firebase_auth_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // =============================================================================
    // MARK: - Auth State
    // =============================================================================

    /**
     * Get current user
     */
    val currentUser: FirebaseUser?
        get() = auth.currentUser

    /**
     * Check if user is authenticated
     */
    val isAuthenticated: Boolean
        get() = auth.currentUser != null

    /**
     * Auth state flow
     */
    val authStateFlow: Flow<FirebaseUser?> = callbackFlow {
        val listener = FirebaseAuth.AuthStateListener { auth ->
            trySend(auth.currentUser)

            // Save or delete token on auth state change
            auth.currentUser?.let {
                saveIdToken()
            } ?: deleteIdToken()
        }

        auth.addAuthStateListener(listener)

        awaitClose {
            auth.removeAuthStateListener(listener)
        }
    }

    // =============================================================================
    // MARK: - Email/Password Authentication
    // =============================================================================

    /**
     * Sign up with email and password
     */
    suspend fun signUp(
        email: String,
        password: String,
        displayName: String? = null
    ): Result<FirebaseUser> {
        return try {
            val result = auth.createUserWithEmailAndPassword(email, password).await()

            // Update display name if provided
            displayName?.let {
                val profileUpdates = UserProfileChangeRequest.Builder()
                    .setDisplayName(it)
                    .build()
                result.user?.updateProfile(profileUpdates)?.await()
            }

            // Send email verification
            result.user?.sendEmailVerification()?.await()

            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Sign in with email and password
     */
    suspend fun signIn(email: String, password: String): Result<FirebaseUser> {
        return try {
            val result = auth.signInWithEmailAndPassword(email, password).await()
            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Sign out
     */
    fun signOut() {
        auth.signOut()
        deleteIdToken()
    }

    /**
     * Send password reset email
     */
    suspend fun resetPassword(email: String): Result<Unit> {
        return try {
            auth.sendPasswordResetEmail(email).await()
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Send email verification
     */
    suspend fun sendEmailVerification(): Result<Unit> {
        return try {
            auth.currentUser?.sendEmailVerification()?.await()
                ?: return Result.failure(Exception("No user logged in"))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Change password
     */
    suspend fun changePassword(currentPassword: String, newPassword: String): Result<Unit> {
        return try {
            val user = auth.currentUser
                ?: return Result.failure(Exception("No user logged in"))

            val email = user.email
                ?: return Result.failure(Exception("User email not found"))

            // Re-authenticate user
            val credential = EmailAuthProvider.getCredential(email, currentPassword)
            user.reauthenticate(credential).await()

            // Update password
            user.updatePassword(newPassword).await()

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // =============================================================================
    // MARK: - Google Sign In
    // =============================================================================

    /**
     * Sign in with Google (use with Google Sign In library)
     */
    suspend fun signInWithGoogle(idToken: String): Result<FirebaseUser> {
        return try {
            val credential = GoogleAuthProvider.getCredential(idToken, null)
            val result = auth.signInWithCredential(credential).await()
            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // =============================================================================
    // MARK: - Phone Authentication
    // =============================================================================

    /**
     * Send verification code to phone number
     */
    fun sendPhoneVerificationCode(
        phoneNumber: String,
        activity: android.app.Activity,
        callbacks: PhoneAuthProvider.OnVerificationStateChangedCallbacks
    ) {
        val options = PhoneAuthOptions.newBuilder(auth)
            .setPhoneNumber(phoneNumber)
            .setTimeout(60L, TimeUnit.SECONDS)
            .setActivity(activity)
            .setCallbacks(callbacks)
            .build()

        PhoneAuthProvider.verifyPhoneNumber(options)
    }

    /**
     * Verify phone number with code
     */
    suspend fun verifyPhoneNumber(
        verificationId: String,
        verificationCode: String
    ): Result<FirebaseUser> {
        return try {
            val credential = PhoneAuthProvider.getCredential(verificationId, verificationCode)
            val result = auth.signInWithCredential(credential).await()
            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // =============================================================================
    // MARK: - Social Authentication (Generic)
    // =============================================================================

    /**
     * Sign in with credential (works for any OAuth provider)
     */
    suspend fun signInWithCredential(credential: AuthCredential): Result<FirebaseUser> {
        return try {
            val result = auth.signInWithCredential(credential).await()
            Result.success(result.user!!)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // =============================================================================
    // MARK: - Token Management
    // =============================================================================

    /**
     * Get Firebase ID token
     */
    suspend fun getIdToken(forceRefresh: Boolean = false): Result<String> {
        return try {
            val user = auth.currentUser
                ?: return Result.failure(Exception("No user logged in"))

            val token = user.getIdToken(forceRefresh).await()
            val idToken = token.token
                ?: return Result.failure(Exception("Failed to get ID token"))

            Result.success(idToken)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Refresh ID token
     */
    suspend fun refreshToken(): Result<String> {
        return getIdToken(forceRefresh = true)
    }

    // =============================================================================
    // MARK: - Secure Token Storage (EncryptedSharedPreferences)
    // =============================================================================

    /**
     * Save ID token to encrypted storage
     */
    private fun saveIdToken() {
        currentUser?.getIdToken(false)?.addOnSuccessListener { result ->
            result.token?.let { token ->
                encryptedPrefs.edit()
                    .putString(KEY_ID_TOKEN, token)
                    .apply()
            }
        }
    }

    /**
     * Get ID token from encrypted storage
     */
    fun getIdTokenFromStorage(): String? {
        return encryptedPrefs.getString(KEY_ID_TOKEN, null)
    }

    /**
     * Delete ID token from encrypted storage
     */
    private fun deleteIdToken() {
        encryptedPrefs.edit()
            .remove(KEY_ID_TOKEN)
            .apply()
    }

    // =============================================================================
    // MARK: - Error Handling
    // =============================================================================

    /**
     * Get user-friendly error message from Firebase exception
     */
    fun getErrorMessage(exception: Exception): String {
        return when (exception) {
            is FirebaseAuthInvalidCredentialsException -> {
                "Invalid email or password"
            }
            is FirebaseAuthInvalidUserException -> {
                when (exception.errorCode) {
                    "ERROR_USER_NOT_FOUND" -> "No account found with this email"
                    "ERROR_USER_DISABLED" -> "This account has been disabled"
                    else -> "Invalid user"
                }
            }
            is FirebaseAuthUserCollisionException -> {
                "An account already exists with this email"
            }
            is FirebaseAuthWeakPasswordException -> {
                "Password is too weak. Use at least 6 characters"
            }
            is FirebaseAuthEmailException -> {
                "Invalid email address"
            }
            is FirebaseNetworkException -> {
                "Network error. Please check your connection"
            }
            is FirebaseTooManyRequestsException -> {
                "Too many requests. Please try again later"
            }
            else -> {
                exception.message ?: "An unknown error occurred"
            }
        }
    }

    companion object {
        private const val KEY_ID_TOKEN = "firebase_id_token"
    }
}

// =============================================================================
// MARK: - Extension Functions
// =============================================================================

/**
 * Get display name or email from FirebaseUser
 */
val FirebaseUser.displayNameOrEmail: String
    get() = displayName ?: email ?: "Unknown User"
