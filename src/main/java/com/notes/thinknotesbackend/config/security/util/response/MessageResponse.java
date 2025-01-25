package com.notes.thinknotesbackend.config.security.util.response;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class MessageResponse { // changed from SignupResponse as it can be reusable
 
    private String message;

    public MessageResponse(String message) {
   
        this.message = message;
    }
}
