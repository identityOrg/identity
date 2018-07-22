package net.prasenjit.identity.oauth.bearer;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.repository.AccessTokenRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

@RequiredArgsConstructor
public class BearerAuthenticationProvider implements AuthenticationProvider {

    private final AccessTokenRepository accessTokenRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (supports(authentication.getClass())) {
            String credentials = (String) authentication.getCredentials();
            Optional<AccessToken> tokenOptional = accessTokenRepository.findById(credentials);
            if (tokenOptional.isPresent()) {
                if (tokenOptional.get().isValid()) {
                    UserDetails userProfile = tokenOptional.get().getUserProfile();
                    return createSuccessAuthentication(userProfile, authentication, userProfile);
                }
            }
        }
        throw new BadCredentialsException("Authentication Failed");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BearerAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Authentication createSuccessAuthentication(Object principal, Authentication authentication, UserDetails user) {
        BearerAuthenticationToken result = new BearerAuthenticationToken(principal, authentication.getCredentials(),
                user.getAuthorities());
        result.setDetails(authentication.getDetails());

        return result;
    }
}
