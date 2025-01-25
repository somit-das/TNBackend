package com.notes.thinknotesbackend.config.security.util.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class LoginResponse {
    private String username;
    private String jwtToken;
    private List<String> roles;

    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.jwtToken = jwtToken;
        this.username = username;
        this.roles = roles;
    }

}
