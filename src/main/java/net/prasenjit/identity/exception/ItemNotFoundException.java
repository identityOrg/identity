package net.prasenjit.identity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_FOUND)
public class ItemNotFoundException extends RuntimeException {
	private static final long serialVersionUID = 7523712521203181151L;

	public ItemNotFoundException(String message) {
        super(message);
    }
}
