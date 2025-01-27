package com.notes.thinknotesbackend.service;

public interface EmailService {
    void sendPasswordResetEmail(String username, String toemail, String resetUrl);
}
