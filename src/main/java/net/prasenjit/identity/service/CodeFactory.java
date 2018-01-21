package net.prasenjit.identity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.repository.AuthorizationCodeRepository;
import net.prasenjit.identity.repository.RefreshTokenRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class CodeFactory {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final ObjectMapper objectMapper;

    public AuthorizationCode createAuthorizationCode(String clientId, String returnUrl, String scope, String userName, String state, Duration validity) {
        AuthorizationCode authorizationCode = new AuthorizationCode();
        authorizationCode.setClientId(clientId);
        LocalDateTime creationDate = LocalDateTime.now();
        authorizationCode.setCreationDate(creationDate);
        authorizationCode.setExpiryDate(creationDate.plus(validity));
        authorizationCode.setReturnUrl(returnUrl);
        authorizationCode.setScope(scope);
        authorizationCode.setUserName(userName);
        authorizationCode.setUsed(false);
        authorizationCode.setState(state);
        authorizationCode.setAuthorizationCode(RandomStringUtils.randomAlphanumeric(8));
        authorizationCodeRepository.saveAndFlush(authorizationCode);
        return authorizationCode;
    }

    public AccessToken createAccessToken(UserDetails user, String clientId, Duration duration, String scope) {
        AccessToken accessToken = new AccessToken();
        accessToken.setAssessToken(RandomStringUtils.randomAlphanumeric(24));
        accessToken.setUserName(user.getUsername());
        LocalDateTime creationDate = LocalDateTime.now();
        accessToken.setCreationDate(creationDate);
        accessToken.setExpiryDate(creationDate.plus(duration));
        accessToken.setUserProfile(serialize(user));
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
        refreshToken.setUserName(userName);
        refreshToken.setRefreshToken(RandomStringUtils.randomAlphanumeric(24));
        refreshToken.setUsageCount(0);
        refreshTokenRepository.saveAndFlush(refreshToken);
        return refreshToken;
    }

    private String serialize(UserDetails user) {
        try {
            return objectMapper.writeValueAsString(user);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize user", e);
            throw new RuntimeException(e);
        }
    }

    public OAuthToken createOAuthToken(AccessToken accessToken, RefreshToken refreshToken1) {
        OAuthToken oAuthToken = new OAuthToken();
        oAuthToken.setAccessToken(accessToken.getAssessToken());
        oAuthToken.setRefreshToken(refreshToken1.getRefreshToken());
        oAuthToken.setTokenType("Bearer");
        oAuthToken.setScope(accessToken.getScope());
        long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        oAuthToken.setExpiresIn(expIn);
        return oAuthToken;
    }
}
