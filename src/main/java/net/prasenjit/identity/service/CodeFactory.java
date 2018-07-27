package net.prasenjit.identity.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.JWKKey;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.model.OAuthToken;
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
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

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

    public AuthorizationCode createAuthorizationCode(String clientId, String returnUrl, String scope, String userName,
                                                     String state, Duration validity, LocalDateTime loginDate,
                                                     boolean openId) {
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
        authorizationCode.setOpenId(openId);
        authorizationCode.setLoginDate(loginDate);
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
        accessToken.setUserProfile(Profile.create(user));
        accessToken.setClientId(clientId);
        accessToken.setScope(scope);
        accessTokenRepository.saveAndFlush(accessToken);
        return accessToken;
    }

    public RefreshToken createRefreshToken(String clientId, String userName, String scope, LocalDateTime loginDate,
                                           Duration duration, boolean openId) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setClientId(clientId);
        LocalDateTime creationDate = LocalDateTime.now();
        refreshToken.setCreationDate(creationDate);
        refreshToken.setExpiryDate(creationDate.plus(duration));
        refreshToken.setScope(scope);
        refreshToken.setUsername(userName);
        refreshToken.setLoginDate(loginDate);
        refreshToken.setOpenId(openId);
        refreshToken.setRefreshToken(RandomStringUtils.randomAlphanumeric(24));
        refreshToken.setUsed(false);
        refreshTokenRepository.saveAndFlush(refreshToken);
        return refreshToken;
    }

    public OAuthToken createOAuthToken(AccessToken accessToken, RefreshToken refreshToken, String idToken) {
        OAuthToken oAuthToken = new OAuthToken();
        oAuthToken.setAccessToken(accessToken.getAssessToken());
        if (refreshToken != null) {
            oAuthToken.setRefreshToken(refreshToken.getRefreshToken());
        }
        oAuthToken.setTokenType("bearer");
        oAuthToken.setScope(accessToken.getScope());
        long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        oAuthToken.setExpiresIn(expIn);
        if (StringUtils.hasText(idToken)) {
            oAuthToken.setIdToken(idToken);
        }
        return oAuthToken;
    }

    public String createCookieToken(Profile user, LocalDateTime loginTime) {
        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUsername())
                    .issuer(metadataService.findMetadata().getIssuer())
                    .issueTime(convertToDate(loginTime))
                    .expirationTime(convertToDate(loginTime.plusDays(identityProperties.getRememberLoginDays())))
                    .build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(macSigner);
            return signedJWT.serialize();
        } catch (JOSEException e) {
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

            LocalDateTime creationTime = convertToLocalDateTime(claimsSet.getIssueTime());

            return new UserAuthenticationToken(claimsSet.getSubject(),
                    userDetails.getPassword(), true, creationTime);
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public String createIDToken(Profile profile, LocalDateTime loginTime, String nonce, String clientId,
                                Duration idTokenValidity, List<String> scope, String accessToken) {
        try {
            LocalDateTime issueTime = LocalDateTime.now();
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .subject(profile.getUsername())
                    .issuer(metadataService.findMetadata().getIssuer())
                    .audience(clientId)
                    .issueTime(convertToDate(issueTime))
                    .expirationTime(convertToDate(issueTime.plus(idTokenValidity)))
                    .claim("auth_time", convertToDate(loginTime))
                    .claim("nonce", nonce)
                    .claim("azp", clientId);
            if (StringUtils.hasText(accessToken)) {
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                sha256.update(accessToken.getBytes(StandardCharsets.US_ASCII));
                byte[] digest = sha256.digest();
                byte[] octate = new byte[16];
                System.arraycopy(digest, 0, octate, 0, 16);
                String atHash = Base64Utils.encodeToUrlSafeString(octate);
                claimsSetBuilder.claim("at_hash", atHash);
            }
            if (scope.contains("profile")) {
                claimsSetBuilder.claim("given_name", profile.getFirstName())
                        .claim("family_name", profile.getLastName());
            }
            JWKKey latestKey = cryptographyService.getOrGenerateJwkKeys().get(0);
            PrivateKey signingKey = cryptographyService.getSigningKey(latestKey);
            claimsSetBuilder.claim("kid", latestKey.getId());
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID("" + latestKey.getId()).build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());
            RSASSASigner signer = new RSASSASigner(signingKey);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Date convertToDate(LocalDateTime tdt) {
        if (tdt == null) {
            return null;
        }
        return Date.from(tdt.atZone(ZoneId.systemDefault()).toInstant());
    }

    private LocalDateTime convertToLocalDateTime(Date date) {
        if (date == null) {
            return null;
        }
        return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime();
    }
}
