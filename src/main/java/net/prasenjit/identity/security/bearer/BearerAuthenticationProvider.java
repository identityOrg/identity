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

package net.prasenjit.identity.security.bearer;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AccessTokenEntity;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.AccessTokenRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RequiredArgsConstructor
public class BearerAuthenticationProvider implements AuthenticationProvider {

    private final AccessTokenRepository accessTokenRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (supports(authentication.getClass())) {
            String credentials = (String) authentication.getCredentials();
            Optional<AccessTokenEntity> tokenOptional = accessTokenRepository.findById(credentials);
            if (tokenOptional.isPresent()) {
                if (tokenOptional.get().isValid()) {
                    return createSuccessAuthentication(tokenOptional.get(), authentication);
                }
            }
        }
        throw new BadCredentialsException("Authentication Failed");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BearerAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Authentication createSuccessAuthentication(AccessTokenEntity accessToken, Authentication authentication) {
        String[] scopes = StringUtils.delimitedListToStringArray(accessToken.getScope(), " ");
        List<Profile.SimpleGrantedAuthority> authorities = Stream.of(scopes)
                .map(Profile.SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        BearerAuthenticationToken result = new BearerAuthenticationToken(accessToken.getUserProfile(),
                authentication.getCredentials(), authorities);
        result.setDetails(authentication.getDetails());

        return result;
    }
}
