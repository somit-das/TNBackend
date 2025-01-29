package com.notes.thinknotesbackend.serviceimpl;

import com.notes.thinknotesbackend.service.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TotpServiceImpl implements TotpService {

    private final GoogleAuthenticator googleAuthenticator;

    public TotpServiceImpl(GoogleAuthenticator googleAuthenticator) {
        this.googleAuthenticator = googleAuthenticator;
    }
    public TotpServiceImpl() {
        this.googleAuthenticator =new GoogleAuthenticator();
    }
    @Override
    public GoogleAuthenticatorKey generateSecretKey() {
        return googleAuthenticator.createCredentials();
    }
    @Override
    public String getQrCodeUrl(GoogleAuthenticatorKey secretKey, String username) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("ThinkNotes",username,secretKey);
    }
    @Override
    public boolean verifyQrCode(String secret, int code) {
        return googleAuthenticator.authorize(secret,code);
    }
}
