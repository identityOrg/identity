package net.prasenjit.identity.exception;

import lombok.Getter;

public class UnauthenticatedClientException extends RuntimeException {
    private static final long serialVersionUID = -1629950979868729270L;
    @Getter
    private final String error;

    public UnauthenticatedClientException(String error, String message) {
        super(message);
        this.error = error;
    }

    public UnauthenticatedClientException(String error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }
}
