/**
 * AuthManager.swift
 * Firebase Authentication Manager for iOS (Swift)
 * Complete production-ready implementation with all auth methods
 */

import Foundation
import FirebaseCore
import FirebaseAuth
import GoogleSignIn
import AuthenticationServices
import Security

// =============================================================================
// MARK: - Auth Manager
// =============================================================================

@MainActor
class AuthManager: ObservableObject {

    // MARK: - Singleton
    static let shared = AuthManager()

    // MARK: - Published Properties
    @Published var user: User?
    @Published var isAuthenticated = false
    @Published var isLoading = false
    @Published var errorMessage: String?

    // MARK: - Private Properties
    private var authStateHandle: AuthStateDidChangeListenerHandle?
    private let auth = Auth.auth()

    // MARK: - Initialization
    private init() {
        // Configure Firebase
        if FirebaseApp.app() == nil {
            FirebaseApp.configure()
        }

        // Set up auth state listener
        setupAuthStateListener()
    }

    // MARK: - Auth State Listener
    private func setupAuthStateListener() {
        authStateHandle = auth.addStateDidChangeListener { [weak self] _, user in
            guard let self = self else { return }

            Task { @MainActor in
                self.user = user
                self.isAuthenticated = user != nil

                // Save ID token to Keychain if user is authenticated
                if let user = user {
                    try? await self.saveIdTokenToKeychain()
                } else {
                    self.deleteIdTokenFromKeychain()
                }
            }
        }
    }

    deinit {
        if let handle = authStateHandle {
            auth.removeStateDidChangeListener(handle)
        }
    }

    // =============================================================================
    // MARK: - Email/Password Authentication
    // =============================================================================

    /// Sign up with email and password
    func signUp(email: String, password: String, displayName: String? = nil) async throws {
        isLoading = true
        errorMessage = nil

        defer { isLoading = false }

        do {
            let authResult = try await auth.createUser(withEmail: email, password: password)

            // Update display name if provided
            if let displayName = displayName {
                let changeRequest = authResult.user.createProfileChangeRequest()
                changeRequest.displayName = displayName
                try await changeRequest.commitChanges()
            }

            // Send email verification
            try await authResult.user.sendEmailVerification()

            self.user = authResult.user

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    /// Sign in with email and password
    func signIn(email: String, password: String) async throws {
        isLoading = true
        errorMessage = nil

        defer { isLoading = false }

        do {
            let authResult = try await auth.signIn(withEmail: email, password: password)
            self.user = authResult.user

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    /// Sign out
    func signOut() throws {
        do {
            try auth.signOut()
            self.user = nil
            self.isAuthenticated = false
            deleteIdTokenFromKeychain()

        } catch {
            throw error
        }
    }

    /// Send password reset email
    func resetPassword(email: String) async throws {
        isLoading = true
        errorMessage = nil

        defer { isLoading = false }

        do {
            try await auth.sendPasswordReset(withEmail: email)
        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    /// Send email verification
    func sendEmailVerification() async throws {
        guard let user = auth.currentUser else {
            throw NSError(domain: "AuthManager", code: 401, userInfo: [
                NSLocalizedDescriptionKey: "No user logged in"
            ])
        }

        try await user.sendEmailVerification()
    }

    /// Change password
    func changePassword(currentPassword: String, newPassword: String) async throws {
        guard let user = auth.currentUser, let email = user.email else {
            throw NSError(domain: "AuthManager", code: 401, userInfo: [
                NSLocalizedDescriptionKey: "No user logged in"
            ])
        }

        // Re-authenticate user
        let credential = EmailAuthProvider.credential(withEmail: email, password: currentPassword)
        try await user.reauthenticate(with: credential)

        // Update password
        try await user.updatePassword(to: newPassword)
    }

    // =============================================================================
    // MARK: - Google Sign In
    // =============================================================================

    /// Sign in with Google
    func signInWithGoogle() async throws {
        guard let clientID = FirebaseApp.app()?.options.clientID else {
            throw NSError(domain: "AuthManager", code: 500, userInfo: [
                NSLocalizedDescriptionKey: "Missing Firebase client ID"
            ])
        }

        // Configure Google Sign In
        let config = GIDConfiguration(clientID: clientID)
        GIDSignIn.sharedInstance.configuration = config

        // Get root view controller
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let rootViewController = windowScene.windows.first?.rootViewController else {
            throw NSError(domain: "AuthManager", code: 500, userInfo: [
                NSLocalizedDescriptionKey: "No root view controller"
            ])
        }

        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            // Start Google Sign In flow
            let result = try await GIDSignIn.sharedInstance.signIn(withPresenting: rootViewController)

            guard let idToken = result.user.idToken?.tokenString else {
                throw NSError(domain: "AuthManager", code: 500, userInfo: [
                    NSLocalizedDescriptionKey: "Missing Google ID token"
                ])
            }

            let accessToken = result.user.accessToken.tokenString

            // Create Firebase credential
            let credential = GoogleAuthProvider.credential(
                withIDToken: idToken,
                accessToken: accessToken
            )

            // Sign in to Firebase
            let authResult = try await auth.signIn(with: credential)
            self.user = authResult.user

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    // =============================================================================
    // MARK: - Apple Sign In
    // =============================================================================

    /// Sign in with Apple
    func signInWithApple(nonce: String, idTokenString: String, rawNonce: String) async throws {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            // Create Firebase credential
            let credential = OAuthProvider.credential(
                withProviderID: "apple.com",
                idToken: idTokenString,
                rawNonce: rawNonce
            )

            // Sign in to Firebase
            let authResult = try await auth.signIn(with: credential)
            self.user = authResult.user

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    // =============================================================================
    // MARK: - Phone Authentication
    // =============================================================================

    /// Send verification code to phone number
    func sendPhoneVerificationCode(phoneNumber: String) async throws -> String {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let verificationID = try await PhoneAuthProvider.provider()
                .verifyPhoneNumber(phoneNumber, uiDelegate: nil)
            return verificationID

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    /// Verify phone number with code
    func verifyPhoneNumber(verificationID: String, verificationCode: String) async throws {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let credential = PhoneAuthProvider.provider().credential(
                withVerificationID: verificationID,
                verificationCode: verificationCode
            )

            let authResult = try await auth.signIn(with: credential)
            self.user = authResult.user

        } catch let error as NSError {
            self.errorMessage = getErrorMessage(error)
            throw error
        }
    }

    // =============================================================================
    // MARK: - Token Management
    // =============================================================================

    /// Get Firebase ID token
    func getIdToken(forceRefresh: Bool = false) async throws -> String? {
        guard let user = auth.currentUser else { return nil }

        do {
            let token = try await user.getIDToken(forcingRefresh: forceRefresh)
            return token
        } catch {
            throw error
        }
    }

    /// Refresh ID token
    func refreshToken() async throws -> String? {
        return try await getIdToken(forceRefresh: true)
    }

    // =============================================================================
    // MARK: - Keychain Management (Secure Token Storage)
    // =============================================================================

    /// Save ID token to Keychain
    private func saveIdTokenToKeychain() async throws {
        guard let token = try await getIdToken() else { return }

        let tokenData = token.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "firebase_id_token",
            kSecValueData as String: tokenData
        ]

        // Delete existing item
        SecItemDelete(query as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)

        if status != errSecSuccess {
            print("Failed to save token to Keychain: \(status)")
        }
    }

    /// Get ID token from Keychain
    func getIdTokenFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "firebase_id_token",
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let tokenData = result as? Data,
              let token = String(data: tokenData, encoding: .utf8) else {
            return nil
        }

        return token
    }

    /// Delete ID token from Keychain
    private func deleteIdTokenFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "firebase_id_token"
        ]

        SecItemDelete(query as CFDictionary)
    }

    // =============================================================================
    // MARK: - Helper Methods
    // =============================================================================

    /// Get user-friendly error message from Firebase error
    private func getErrorMessage(_ error: NSError) -> String {
        guard let errorCode = AuthErrorCode.Code(rawValue: error.code) else {
            return "An unknown error occurred"
        }

        switch errorCode {
        case .invalidEmail:
            return "Invalid email address"
        case .emailAlreadyInUse:
            return "Email address is already in use"
        case .weakPassword:
            return "Password is too weak. Use at least 6 characters"
        case .wrongPassword:
            return "Incorrect password"
        case .userNotFound:
            return "No account found with this email"
        case .userDisabled:
            return "This account has been disabled"
        case .tooManyRequests:
            return "Too many requests. Please try again later"
        case .networkError:
            return "Network error. Please check your connection"
        case .invalidCredential:
            return "Invalid credentials. Please try again"
        default:
            return error.localizedDescription
        }
    }
}

// =============================================================================
// MARK: - User Extension
// =============================================================================

extension User {
    /// Get user's display name or email
    var displayNameOrEmail: String {
        displayName ?? email ?? "Unknown User"
    }
}
