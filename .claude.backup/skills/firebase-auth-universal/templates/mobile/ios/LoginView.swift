/**
 * LoginView.swift
 * SwiftUI Login Screen with Firebase Authentication
 * Supports email/password, Google, and Apple Sign In
 */

import SwiftUI
import FirebaseAuth
import AuthenticationServices
import CryptoKit

struct LoginView: View {
    @StateObject private var authManager = AuthManager.shared

    @State private var email = ""
    @State private var password = ""
    @State private var showingError = false
    @State private var showingResetPassword = false
    @State private var resetEmailSent = false
    @State private var currentNonce: String?

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Header
                    VStack(spacing: 8) {
                        Image(systemName: "lock.shield")
                            .font(.system(size: 60))
                            .foregroundColor(.blue)

                        Text("Sign In")
                            .font(.largeTitle)
                            .fontWeight(.bold)
                    }
                    .padding(.top, 40)

                    // Email/Password Form
                    VStack(spacing: 16) {
                        TextField("Email", text: $email)
                            .textContentType(.emailAddress)
                            .keyboardType(.emailAddress)
                            .autocapitalization(.none)
                            .padding()
                            .background(Color(.systemGray6))
                            .cornerRadius(10)

                        SecureField("Password", text: $password)
                            .textContentType(.password)
                            .padding()
                            .background(Color(.systemGray6))
                            .cornerRadius(10)

                        // Forgot Password Button
                        HStack {
                            Spacer()
                            Button("Forgot password?") {
                                showingResetPassword = true
                            }
                            .font(.footnote)
                            .foregroundColor(.blue)
                        }

                        // Sign In Button
                        Button(action: handleEmailSignIn) {
                            if authManager.isLoading {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Text("Sign In")
                                    .fontWeight(.semibold)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                        .disabled(authManager.isLoading || email.isEmpty || password.isEmpty)
                    }
                    .padding(.horizontal)

                    // Divider
                    HStack {
                        VStack { Divider() }
                        Text("OR")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                        VStack { Divider() }
                    }
                    .padding(.horizontal)

                    // Social Sign In Buttons
                    VStack(spacing: 12) {
                        // Google Sign In
                        Button(action: handleGoogleSignIn) {
                            HStack {
                                Image(systemName: "g.circle.fill")
                                    .font(.title2)
                                Text("Continue with Google")
                                    .fontWeight(.medium)
                            }
                            .frame(maxWidth: .infinity)
                            .frame(height: 50)
                            .background(Color.white)
                            .foregroundColor(.black)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                            )
                            .cornerRadius(10)
                        }
                        .disabled(authManager.isLoading)

                        // Apple Sign In
                        SignInWithAppleButton(
                            .signIn,
                            onRequest: { request in
                                let nonce = randomNonceString()
                                currentNonce = nonce
                                request.requestedScopes = [.fullName, .email]
                                request.nonce = sha256(nonce)
                            },
                            onCompletion: { result in
                                handleAppleSignIn(result)
                            }
                        )
                        .signInWithAppleButtonStyle(.black)
                        .frame(height: 50)
                        .cornerRadius(10)
                        .disabled(authManager.isLoading)
                    }
                    .padding(.horizontal)

                    // Sign Up Link
                    HStack {
                        Text("Don't have an account?")
                            .foregroundColor(.secondary)
                        NavigationLink("Sign Up", destination: SignUpView())
                            .fontWeight(.semibold)
                    }
                    .padding(.top, 16)

                    Spacer()
                }
            }
            .navigationBarHidden(true)
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(authManager.errorMessage ?? "An unknown error occurred")
            }
            .sheet(isPresented: $showingResetPassword) {
                PasswordResetView(isPresented: $showingResetPassword)
            }
        }
    }

    // MARK: - Email Sign In
    private func handleEmailSignIn() {
        Task {
            do {
                try await authManager.signIn(email: email, password: password)
            } catch {
                showingError = true
            }
        }
    }

    // MARK: - Google Sign In
    private func handleGoogleSignIn() {
        Task {
            do {
                try await authManager.signInWithGoogle()
            } catch {
                showingError = true
            }
        }
    }

    // MARK: - Apple Sign In
    private func handleAppleSignIn(_ result: Result<ASAuthorization, Error>) {
        switch result {
        case .success(let authorization):
            guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential,
                  let nonce = currentNonce,
                  let appleIDToken = appleIDCredential.identityToken,
                  let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
                authManager.errorMessage = "Failed to get Apple credentials"
                showingError = true
                return
            }

            Task {
                do {
                    try await authManager.signInWithApple(
                        nonce: sha256(nonce),
                        idTokenString: idTokenString,
                        rawNonce: nonce
                    )
                } catch {
                    showingError = true
                }
            }

        case .failure(let error):
            authManager.errorMessage = error.localizedDescription
            showingError = true
        }
    }

    // MARK: - Apple Sign In Helpers
    private func randomNonceString(length: Int = 32) -> String {
        precondition(length > 0)
        let charset: [Character] =
        Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        var result = ""
        var remainingLength = length

        while remainingLength > 0 {
            let randoms: [UInt8] = (0 ..< 16).map { _ in
                var random: UInt8 = 0
                let errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random)
                if errorCode != errSecSuccess {
                    fatalError("Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)")
                }
                return random
            }

            randoms.forEach { random in
                if remainingLength == 0 {
                    return
                }

                if random < charset.count {
                    result.append(charset[Int(random)])
                    remainingLength -= 1
                }
            }
        }

        return result
    }

    private func sha256(_ input: String) -> String {
        let inputData = Data(input.utf8)
        let hashedData = SHA256.hash(data: inputData)
        let hashString = hashedData.compactMap {
            String(format: "%02x", $0)
        }.joined()

        return hashString
    }
}

// =============================================================================
// MARK: - Password Reset View
// =============================================================================

struct PasswordResetView: View {
    @StateObject private var authManager = AuthManager.shared
    @Binding var isPresented: Bool

    @State private var email = ""
    @State private var emailSent = false
    @State private var showingError = false

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                if emailSent {
                    // Success State
                    VStack(spacing: 16) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.green)

                        Text("Email Sent!")
                            .font(.title)
                            .fontWeight(.bold)

                        Text("Check your inbox for password reset instructions.")
                            .multilineTextAlignment(.center)
                            .foregroundColor(.secondary)
                            .padding(.horizontal)

                        Button("Done") {
                            isPresented = false
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                        .padding(.horizontal)
                    }
                } else {
                    // Email Input
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Reset Password")
                            .font(.title)
                            .fontWeight(.bold)

                        Text("Enter your email address and we'll send you instructions to reset your password.")
                            .foregroundColor(.secondary)

                        TextField("Email", text: $email)
                            .textContentType(.emailAddress)
                            .keyboardType(.emailAddress)
                            .autocapitalization(.none)
                            .padding()
                            .background(Color(.systemGray6))
                            .cornerRadius(10)

                        Button(action: handleResetPassword) {
                            if authManager.isLoading {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            } else {
                                Text("Send Reset Email")
                                    .fontWeight(.semibold)
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 50)
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                        .disabled(authManager.isLoading || email.isEmpty)
                    }
                    .padding()
                }

                Spacer()
            }
            .padding(.top, 40)
            .navigationBarItems(
                leading: Button("Cancel") {
                    isPresented = false
                }
            )
            .alert("Error", isPresented: $showingError) {
                Button("OK", role: .cancel) { }
            } message: {
                Text(authManager.errorMessage ?? "An unknown error occurred")
            }
        }
    }

    private func handleResetPassword() {
        Task {
            do {
                try await authManager.resetPassword(email: email)
                emailSent = true
            } catch {
                showingError = true
            }
        }
    }
}

// =============================================================================
// MARK: - Sign Up View (Placeholder)
// =============================================================================

struct SignUpView: View {
    var body: some View {
        Text("Sign Up View")
            .navigationTitle("Sign Up")
    }
}

// =============================================================================
// MARK: - Preview
// =============================================================================

struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView()
    }
}
