package net.prasenjit.identity.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.repository.AuthorizationCodeRepository;
import net.prasenjit.identity.repository.RefreshTokenRepository;

//@Slf4j
@Component
@RequiredArgsConstructor
public class CodeFactory {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;

    public AuthorizationCode createAuthorizationCode(String clientId, String returnUrl, String scope, String userName, String state, Duration validity) {
        AuthorizationCode authorizationCode = new AuthorizationCode();
        authorizationCode.setClientId(clientId);
        LocalDateTime creationDate = LocalDateTime.now();
        authorizationCode.setCreationDate(creationDate);
        authorizationCode.setExpiryDate(creationDate.plus(validity));
        authorizationCode.setReturnUrl(returnUrl);
        authorizationCode.setScope(scope);
        authorizationCode.setUsername(userName);
        authorizationCode.setUsed(false);
        authorizationCode.setState(state);
        authorizationCode.setAuthorizationCode(RandomStringUtils.randomAlphanumeric(8));
        authorizationCodeRepository.saveAndFlush(authorizationCode);
        return authorizationCode;
    }

    public AccessToken createAccessToken(UserDetails user, String clientId, Duration duration, String scope) {
        AccessToken accessToken = new AccessToken();
        accessToken.setAssessToken(RandomStringUtils.randomAlphanumeric(24));
        accessToken.setUsername(user.getUsername());
        LocalDateTime creationDate = LocalDateTime.now();
        accessToken.setCreationDate(creationDate);
        accessToken.setExpiryDate(creationDate.plus(duration));
        accessToken.setUserProfile(user);
        accessToken.setClientId(clientId);
        accessToken.setScope(scope);
        accessTokenRepository.saveAndFlush(accessToken);
        return accessToken;
    }

    public RefreshToken createRefreshToken(String clientId, String userName, String scope, Duration duration) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setClientId(clientId);
        LocalDateTime creationDate = LocalDateTime.now();
        refreshToken.setCreationDate(creationDate);
        refreshToken.setExpiryDate(creationDate.plus(duration));
        refreshToken.setScope(scope);
        refreshToken.setUsername(userName);
        refreshToken.setRefreshToken(RandomStringUtils.randomAlphanumeric(24));
        refreshToken.setUsed(false);
        refreshTokenRepository.saveAndFlush(refreshToken);
        return refreshToken;
    }

    public OAuthToken createOAuthToken(AccessToken accessToken, RefreshToken refreshToken) {
        OAuthToken oAuthToken = new OAuthToken();
        oAuthToken.setAccessToken(accessToken.getAssessToken());
        if (refreshToken != null) {
            oAuthToken.setRefreshToken(refreshToken.getRefreshToken());
        }
        oAuthToken.setTokenType("bearer");
        oAuthToken.setScope(accessToken.getScope());
        long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        oAuthToken.setExpiresIn(expIn);
        return oAuthToken;
    }
}
