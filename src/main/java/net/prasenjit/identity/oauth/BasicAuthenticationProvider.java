/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.prasenjit.identity.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

@Slf4j
@RequiredArgsConstructor
public class BasicAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private UserCache userCache = new NullUserCache();
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    private void additionalAuthenticationChecks(UserDetails userDetails, BasicAuthenticationToken authentication)
            throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            log.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException("Bad credentials");
        }

        String presentedPassword = authentication.getCredentials().toString();

        if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            log.debug("Authentication failed: password does not match stored value");

            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userCache, "A user cache must be set");
        Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(BasicAuthenticationToken.class, authentication,
                "Only BasicAuthenticationToken is supported");

        // Determine username
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();

        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);

        if (user == null) {
            cacheWasUsed = false;

            try {
                user = retrieveUser(username, (BasicAuthenticationToken) authentication);
            } catch (UsernameNotFoundException notFound) {
                log.debug("User '{}' not found", username);
                throw new BadCredentialsException("Bad credentials");
            }

            Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
        }

        try {
            this.preAuthenticationCheck(user);
            additionalAuthenticationChecks(user, (BasicAuthenticationToken) authentication);
        } catch (AuthenticationException exception) {
            if (cacheWasUsed) {
                cacheWasUsed = false;
                user = retrieveUser(username, (BasicAuthenticationToken) authentication);
                this.preAuthenticationCheck(user);
                additionalAuthenticationChecks(user, (BasicAuthenticationToken) authentication);
            } else {
                throw exception;
            }
        }

        this.postAuthenticationCheck(user);

        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user;

        return createSuccessAuthentication(principalToReturn, authentication, user);
    }

    public boolean supports(Class<?> authentication) {
        return (BasicAuthenticationToken.class.isAssignableFrom(authentication));
    }

    private Authentication createSuccessAuthentication(Object principal, Authentication authentication,
                                                       UserDetails user) {
        BasicAuthenticationToken result = new BasicAuthenticationToken(principal, authentication.getCredentials(),
                authoritiesMapper.mapAuthorities(user.getAuthorities()));

        result.setDetails(authentication.getDetails());
        return result;
    }

    private UserDetails retrieveUser(String username, BasicAuthenticationToken authentication)
            throws AuthenticationException {
        UserDetails loadedUser;

        try {
            loadedUser = this.userDetailsService.loadUserByUsername(username);
        } catch (Exception repositoryProblem) {
            throw new InternalAuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (loadedUser == null) {
            throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        return loadedUser;
    }

    private void preAuthenticationCheck(UserDetails user) {
        if (!user.isAccountNonLocked()) {
            log.debug("User account is locked");
            throw new LockedException("User account is locked");
        }

        if (!user.isEnabled()) {
            log.debug("User account is disabled");
            throw new DisabledException("User is disabled");
        }

        if (!user.isAccountNonExpired()) {
            log.debug("User account is expired");
            throw new AccountExpiredException("User account has expired");
        }
    }

    private void postAuthenticationCheck(UserDetails user) {
        if (!user.isCredentialsNonExpired()) {
            log.debug("User account credentials have expired");

            throw new CredentialsExpiredException("User credentials have expired");
        }
    }

}
