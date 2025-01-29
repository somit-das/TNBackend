package com.notes.thinknotesbackend.controller;

import com.notes.thinknotesbackend.config.security.util.JwtUtils;
import com.notes.thinknotesbackend.config.security.util.request.LoginRequest;
import com.notes.thinknotesbackend.config.security.util.request.SignUpRequest;
import com.notes.thinknotesbackend.config.security.util.response.MessageResponse;
import com.notes.thinknotesbackend.service.AuthService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {



    @Autowired
    private AuthService authService;
    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        return authService.authenticateUser(loginRequest);
    }

    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        return authService.registerUser(signUpRequest);
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        return authService.getUserDetails(userDetails);

    }
    @GetMapping("/username")
    public String getUserame(@AuthenticationPrincipal UserDetails userDetails) {

        return authService.getUserName(userDetails);
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try{
            authService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password reset email sent"));

        } catch (Exception e) {
            System.out.println(e.getMessage());
             return ResponseEntity.status(HttpStatus.BAD_REQUEST).
                     body(new MessageResponse(e.getMessage()));

        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token,@RequestParam String newPassword) {
        try{
            authService.resetPassword(token,newPassword);
            return ResponseEntity.ok(new MessageResponse("Password reset token successful"));
        }catch(RuntimeException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(e.getMessage()));

        }
    }
    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enable2FA() {
        return authService.enable2FA();
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disable2FA() {
        return authService.disable2FA();
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<?> verify2FA(@RequestParam int code) {
        return authService.verify2FA(code);
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        return authService.get2FAStatus();
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<?> vefify2FALogin(@RequestParam int code,@RequestParam String jwtToken) {
        return authService.verify2FALogin(code,jwtToken);
    }

    @PostMapping("/update-credentials")
    public ResponseEntity<?> updateCredentials(@RequestParam String jwtToken, @RequestParam String newUsername,@RequestParam String newPassword) {
        System.out.println(jwtToken  + newUsername + newPassword);
        return authService.updateCredentials(jwtToken,newUsername,newPassword);
    }

    @PutMapping("/update-expiry-status")
    public ResponseEntity<?> updateExpiryStatus(@RequestParam String jwtToken, @RequestParam Boolean expiryStatus) {

        return authService.updateExpiryStatus(jwtToken,expiryStatus);
    }

    @PutMapping("/update-lock-status")
    public ResponseEntity<?> updateLockStatus(@RequestParam String jwtToken, @RequestParam Boolean lockStatus) {
        return authService.updateLockStatus(jwtToken,lockStatus);
    }
    @PutMapping("/update-enabled-status")
    public ResponseEntity<?> updateEnabledStatus(@RequestParam String jwtToken, @RequestParam Boolean enabledStatus) {
        return authService.updateEnabledStatus(jwtToken,enabledStatus);
    }
    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<?> updateCredentialsExpiryStatus(@RequestParam String jwtToken, @RequestParam Boolean expiryStatus) {
        return authService.updateCredentialsExpiryStatus(jwtToken,expiryStatus);
    }
}