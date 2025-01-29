package com.notes.thinknotesbackend.service;


import com.notes.thinknotesbackend.config.security.util.request.LoginRequest;
import com.notes.thinknotesbackend.config.security.util.request.SignUpRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthService {
    ResponseEntity<?> authenticateUser(LoginRequest loginRequest);


    ResponseEntity<?> registerUser(@Valid SignUpRequest signUpRequest);

    ResponseEntity<?> getUserDetails(UserDetails userDetails);

    String getUserName(UserDetails userDetails);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String newPassword);

    ResponseEntity<?> enable2FA();

    ResponseEntity<?> disable2FA();

    ResponseEntity<?> verify2FA(int code);

    ResponseEntity<?> get2FAStatus();

    ResponseEntity<?> verify2FALogin(int code, String jwtToken);

    ResponseEntity<?> updateCredentials(String jwtToken, String newUsername, String newPassword);

    ResponseEntity<?> updateExpiryStatus(String jwtToken, Boolean expiryStatus);

    ResponseEntity<?> updateLockStatus(String jwtToken, Boolean lockStatus);

    ResponseEntity<?> updateEnabledStatus(String jwtToken, Boolean enabledStatus);

    ResponseEntity<?> updateCredentialsExpiryStatus(String jwtToken, Boolean expiryStatus);
}
