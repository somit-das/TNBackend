package com.notes.thinknotesbackend.exception;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@NoArgsConstructor
@ToString
public class InvalidDataException extends RuntimeException {
    private String message;

    public InvalidDataException(String message) {
        this.message = message;
    }
    public String getMessage() {
        return message;
    }
}
