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

package net.prasenjit.identity.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.entity.AccessTokenEntity;
import net.prasenjit.identity.entity.AuthorizationCodeEntity;
import net.prasenjit.identity.entity.RefreshTokenEntity;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.repository.AuthorizationCodeRepository;
import net.prasenjit.identity.repository.RefreshTokenRepository;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.openid.CryptographyService;
import net.prasenjit.identity.service.openid.MetadataService;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

//@Slf4j
@Component
@RequiredArgsConstructor
public class CodeFactory {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final MetadataService metadataService;
    private final IdentityProperties identityProperties;
    private final CryptoKeyFactory cryptoKeyFactory;
    private final UserService userService;
    private final CryptographyService cryptographyService;

    private MACSigner macSigner;
    private MACVerifier macVerifier;

    @PostConstruct
    public void init() throws JOSEException {
        SecretKey mainKey = cryptoKeyFactory.getSecretKey("main",
                identityProperties.getCryptoProperties().getMainKeyPassword().toCharArray());
        macSigner = new MACSigner(mainKey);
        macVerifier = new MACVerifier(mainKey);
    }

    AuthorizationCode createAuthorizationCode(ClientID clientId, URI returnUrl, Scope scope, String userName,
                                              State state, Duration validity, LocalDateTime loginDate,
                                              CodeChallenge challenge, CodeChallengeMethod method, boolean openId) {
        AuthorizationCodeEntity authorizationCode = new AuthorizationCodeEntity();
        authorizationCode.setClientId(clientId.getValue());
        LocalDateTime creationDate = LocalDateTime.now();
        authorizationCode.setCreationDate(creationDate);
        authorizationCode.setExpiryDate(creationDate.plus(validity));
        authorizationCode.setReturnUrl(returnUrl == null ? null : returnUrl.toString());
        authorizationCode.setScope(scope.toString());
        authorizationCode.setUsername(userName);
        authorizationCode.setUsed(false);
        if (state != null) {
            authorizationCode.setState(state.getValue());
        }
        if (challenge != null && method != null) {
            authorizationCode.setChallenge(challenge.getValue());
            authorizationCode.setChallengeMethod(method.getValue());
        }
        authorizationCode.setOpenId(openId);
        authorizationCode.setLoginDate(loginDate);
        int codeLength = identityProperties.getCodeProperty().getAuthorizationCodeLength();
        authorizationCode.setAuthorizationCode(RandomStringUtils.randomAlphanumeric(codeLength));
        authorizationCodeRepository.saveAndFlush(authorizationCode);
        return new AuthorizationCode(authorizationCode.getAuthorizationCode());
    }

    public BearerAccessToken createAccessToken(Profile user, ClientID clientId, Duration duration,
                                               Scope scope, LocalDateTime loginDate, String refreshToken) {
        user.setAssociatedClient(clientId.getValue());
        AccessTokenEntity accessToken = new AccessTokenEntity();
        accessToken.setAssessToken(RandomStringUtils.randomAlphanumeric(24));
        accessToken.setUsername(user.getUsername());
        LocalDateTime creationDate = LocalDateTime.now();
        accessToken.setCreationDate(creationDate);
        accessToken.setExpiryDate(creationDate.plus(duration));
        accessToken.setUserProfile(user);
        accessToken.setClientId(clientId.getValue());
        if (scope != null) {
            accessToken.setScope(scope.toString());
        }
        accessToken.setRefreshToken(refreshToken);
        accessToken.setLoginDate(loginDate);
        accessTokenRepository.saveAndFlush(accessToken);
        long lifetime = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        return new BearerAccessToken(accessToken.getAssessToken(), lifetime, scope);
    }

    RefreshToken createRefreshToken(ClientID clientId, String userName, Scope scope, LocalDateTime loginDate,
                                    Duration duration, boolean openId, String parentRefreshToken) {
        RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        refreshToken.setClientId(clientId.getValue());
        LocalDateTime creationDate = LocalDateTime.now();
        refreshToken.setCreationDate(creationDate);
        refreshToken.setExpiryDate(creationDate.plus(duration));
        if (scope != null) {
            refreshToken.setScope(scope.toString());
        }
        refreshToken.setUsername(userName);
        refreshToken.setLoginDate(loginDate);
        refreshToken.setOpenId(openId);
        refreshToken.setRefreshToken(RandomStringUtils.randomAlphanumeric(24));
        refreshToken.setUsed(false);
        refreshToken.setParentRefreshToken(parentRefreshToken);
        refreshTokenRepository.saveAndFlush(refreshToken);
        return new RefreshToken(refreshToken.getRefreshToken());
    }

    public String createCookieToken(String username, LocalDateTime loginTime) {
        try {
            UserDetails userDetails = userService.loadUserByUsername(username);
            String hash = generateHash(userDetails.getPassword());
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(username)
                    .issuer(metadataService.findOIDCConfiguration().getIssuer().getValue())
                    .issueTime(ValidationUtils.convertToDate(loginTime))
                    .expirationTime(ValidationUtils.convertToDate(
                            loginTime.plusDays(identityProperties.getRememberLoginDays())))
                    .claim("p_hash", hash)
                    .build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(macSigner);
            return signedJWT.serialize();
        } catch (JOSEException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public UserAuthenticationToken decodeCookieToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            signedJWT.verify(macVerifier);

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            UserDetails userDetails = userService.loadUserByUsername(claimsSet.getSubject());
            if (!userDetails.isAccountNonExpired() || !userDetails.isAccountNonLocked()
                    || !userDetails.isCredentialsNonExpired() || !userDetails.isEnabled()) {
                return null;
            }
            String hash = generateHash(userDetails.getPassword());
            if (!hash.equals(claimsSet.getClaim("p_hash"))) {
                return null;
            }

            LocalDateTime creationTime = ValidationUtils.convertToLocalDateTime(claimsSet.getIssueTime());

            return new UserAuthenticationToken(claimsSet.getSubject(),
                    userDetails.getPassword(), true, creationTime);
        } catch (ParseException | JOSEException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    JWT createIDToken(Profile profile, LocalDateTime loginTime, Nonce nonce, ClientID clientId,
                      Duration idTokenValidity, Scope scope, AccessToken accessToken, AuthorizationCode authCode) {
        try {
            LocalDateTime issueTime = LocalDateTime.now();
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .subject(profile.getUsername())
                    .issuer(metadataService.findOIDCConfiguration().getIssuer().getValue())
                    .audience(clientId.getValue())
                    .issueTime(ValidationUtils.convertToDate(issueTime))
                    .expirationTime(ValidationUtils.convertToDate(issueTime.plus(idTokenValidity)))
                    .claim("auth_time", ValidationUtils.convertToDate(loginTime))
                    .claim("azp", clientId.getValue());
            if (nonce != null) {
                claimsSetBuilder.claim("nonce", nonce.getValue());
            }
            if (accessToken != null) {
                String atHash = generateHash(accessToken.getValue());
                claimsSetBuilder.claim("at_hash", atHash);
            }
            if (authCode != null) {
                String cHash = generateHash(authCode.getValue());
                claimsSetBuilder.claim("c_hash", cHash);
            }
            if (scope.contains("profile")) {
                claimsSetBuilder.claim("given_name", profile.getFirstName())
                        .claim("family_name", profile.getLastName());
            }
            JWKSet keySet = cryptographyService.loadJwkKeys();
            JWK signingKey = keySet.getKeyByKeyId("jwk-sig");
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID()).build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());
            RSASSASigner signer = new RSASSASigner((RSAKey) signingKey);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private String generateHash(String accessToken) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(accessToken.getBytes(StandardCharsets.US_ASCII));
        byte[] digest = sha256.digest();
        byte[] octate = new byte[digest.length / 2];
        System.arraycopy(digest, 0, octate, 0, octate.length);
        return Base64Utils.encodeToUrlSafeString(octate);
    }
}
