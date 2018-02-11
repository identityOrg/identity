package net.prasenjit.identity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_MODIFIED)
public class OperationIgnoredException extends RuntimeException {
    public OperationIgnoredException(String message) {
        super(message);
    }
}
