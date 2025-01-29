package com.notes.thinknotesbackend.exception;

import lombok.*;

@Setter
@Getter
@ToString
public class SameLoginEmailProvider extends RuntimeException {
    private String message;

    public SameLoginEmailProvider(String message) {
        this.message = message;
    }
    public String getMessage() {
        return message;
    }
}
