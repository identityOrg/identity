package net.prasenjit.identity.config;

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;

import static net.prasenjit.identity.properties.ApplicationConstants.LOGIN_TIME;
import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Component
public class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler,
        AuthenticationEntryPoint {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof CredentialsExpiredException) {
            response.sendRedirect("/changePassword");
        } else {
            response.sendRedirect("/login?error");
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String requestURI = (String) request.getSession().getAttribute(PREVIOUS_URL);
        request.getSession().setAttribute(LOGIN_TIME, LocalDateTime.now());
        if (requestURI != null) {
            response.sendRedirect(requestURI);
        } else {
            response.sendRedirect("/");
        }
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromRequest(request);
        request.getSession().setAttribute(PREVIOUS_URL, builder.build().toString());
        response.sendRedirect("/login");
    }
}
