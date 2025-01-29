package com.notes.thinknotesbackend.controller;

import com.notes.thinknotesbackend.config.security.util.request.LoginRequest;
import com.notes.thinknotesbackend.config.security.util.request.SignUpRequest;
import com.notes.thinknotesbackend.config.security.util.response.MessageResponse;
import com.notes.thinknotesbackend.service.AuthService;
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
}