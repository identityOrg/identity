package net.prasenjit.identity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class ErrorHandlerAdvice {

    @ResponseBody
    @ResponseStatus(code = HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = OAuthException.class)
    public Map<String, String> handleTokenError(OAuthException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("code", ex.getError());
        response.put("description", ex.getMessage());
        return response;
    }

    @ResponseBody
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(value = UnauthenticatedClientException.class)
    public Map<String, String> clientAuthenticationRequired(UnauthenticatedClientException ex, HttpServletResponse httpServletResponse) {
        Map<String, String> response = new HashMap<>();
        response.put("code", ex.getError());
        response.put("description", ex.getMessage());
        httpServletResponse.addHeader("WWW-Authenticate", "default");
        return response;
    }
}
