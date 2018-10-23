/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.LocalDateTime;

import static net.prasenjit.identity.properties.ApplicationConstants.LOGIN_TIME;
import static net.prasenjit.identity.properties.ApplicationConstants.PASSWORD_CHANGE_FORCED_FOR;
import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Component
public class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler,
        AuthenticationEntryPoint {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        if (exception instanceof CredentialsExpiredException) {
            HttpSession httpSession = request.getSession();
            String username = request.getParameter("username");
            httpSession.setAttribute(PASSWORD_CHANGE_FORCED_FOR, username);
            response.sendRedirect("/change-password");
        } else {
            response.sendRedirect("/login?error");
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
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
