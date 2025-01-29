package com.notes.thinknotesbackend.service;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

@Service
public interface TotpService {
    GoogleAuthenticatorKey generateSecretKey();

    String getQrCodeUrl(GoogleAuthenticatorKey secretKey, String username);

    boolean verifyQrCode(String secret, int code);
}
