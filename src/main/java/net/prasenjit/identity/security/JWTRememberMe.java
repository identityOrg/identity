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

package net.prasenjit.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.CodeFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class JWTRememberMe implements RememberMeServices, LogoutHandler {

    private static final String COOKIE_NAME = "S_CONTEXT";

    private final CodeFactory codeFactory;
    private final IdentityProperties identityProperties;
    @Setter
    private Boolean useSecureCookie = false;

    @Override
    public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(COOKIE_NAME)) {
                String cookieBody = cookie.getValue();
                return codeFactory.decodeCookieToken(cookieBody);
            }
        }
        return null;
    }

    @Override
    public void loginFail(HttpServletRequest request, HttpServletResponse response) {
        setCookie("", 0, request, response);
    }

    @Override
    public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        if (successfulAuthentication instanceof UserAuthenticationToken) {
            Profile profile = (Profile) successfulAuthentication.getPrincipal();
            LocalDateTime loginTime = ((UserAuthenticationToken) successfulAuthentication).getLoginTime();
            String idToken = codeFactory.createCookieToken(profile.getUsername(), loginTime);
            setCookie(idToken, getTokenValiditySeconds(), request, response);
        }
    }

    private int getTokenValiditySeconds() {
        return identityProperties.getRememberLoginDays() * 24 * 60 * 60;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        loginFail(request, response);
    }

    private void setCookie(String token, int maxAge, HttpServletRequest request,
                           HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setMaxAge(maxAge);
        cookie.setPath(getCookiePath(request));
        if (maxAge < 1) {
            cookie.setVersion(1);
        }
        if (useSecureCookie == null) {
            cookie.setSecure(request.isSecure());
        } else {
            cookie.setSecure(useSecureCookie);
        }
        cookie.setHttpOnly(true);

        response.addCookie(cookie);
    }

    private String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath.length() > 0 ? contextPath : "/";
    }
}
