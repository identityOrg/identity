package net.prasenjit.identity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class ErrorHandlerAdvice {

    @ExceptionHandler(value = OAuthException.class)
    @ResponseBody
    @ResponseStatus(code = HttpStatus.BAD_REQUEST)
    public Map<String, String> handleTokenError(OAuthException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("code", ex.getError());
        response.put("description", ex.getMessage());
        return response;
    }
}
