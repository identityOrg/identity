package net.prasenjit.identity.exception;

import lombok.Getter;

public class OAuthException extends RuntimeException {
    private static final long serialVersionUID = -1629950979868729249L;
    @Getter
    private final String error;

    public OAuthException(String error, String message) {
        super(message);
        this.error = error;
    }

    public OAuthException(String error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }
}
