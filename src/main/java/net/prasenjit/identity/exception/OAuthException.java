package net.prasenjit.identity.exception;

public class OAuthException extends RuntimeException {
	private static final long serialVersionUID = -1629950979868729249L;

	public OAuthException(String message) {
        super(message);
    }

    public OAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
