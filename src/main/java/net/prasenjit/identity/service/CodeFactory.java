package net.prasenjit.identity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.model.AuthorizationModel;
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

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
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
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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
        accessToken.setUserProfile(Profile.create(user));
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

    public String createCookieToken(Profile user, LocalDateTime loginTime) {
        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUsername())
                    .issuer(metadataService.findMetadata().getIssuer())
                    .issueTime(convertToDate(loginTime))
                    .expirationTime(convertToDate(loginTime.plusDays(identityProperties.getRememberLoginDays())))
//                    .claim("profile.active", user.getActive())
//                    .claim("profile.expiryDate", convertToDate(user.getExpiryDate()))
//                    .claim("profile.passwordExpiryDate", convertToDate(user.getPasswordExpiryDate()))
//                    .claim("profile.authorities", OBJECT_MAPPER.writeValueAsString(user.getAuthorities()))
//                    .claim("profile.creationDate", convertToDate(user.getCreationDate()))
//                    .claim("profile.firstName", user.getFirstName())
//                    .claim("profile.lastName", user.getLastName())
//                    .claim("profile.status", user.getStatus())
//                    .claim("profile.locked", user.getLocked())
//                    .claim("profile.client", user.isClient())
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

//            Profile profile = new Profile();
//            profile.setActive(claimsSet.getBooleanClaim("profile.active"));
//            profile.setClient(claimsSet.getBooleanClaim("profile.client"));
//            profile.setCreationDate(convertToLocalDateTime(claimsSet.getDateClaim("profile.creationDate")));
//            profile.setExpiryDate(convertToLocalDateTime(claimsSet.getDateClaim("profile.expiryDate")));
//            profile.setFirstName(claimsSet.getStringClaim("profile.firstName"));
//            profile.setLastName(claimsSet.getStringClaim("profile.lastName"));
//            profile.setLocked(claimsSet.getBooleanClaim("profile.locked"));
//            profile.setPasswordExpiryDate(convertToLocalDateTime(claimsSet.getDateClaim("profile.passwordExpiryDate")));
//            String statusClaim = claimsSet.getStringClaim("profile.status");
//            if (StringUtils.hasText(statusClaim)) {
//                profile.setStatus(Status.valueOf(statusClaim));
//            }
//            profile.setUsername(claimsSet.getSubject());
//            SimpleGrantedAuthority[] simpleGrantedAuthorities = OBJECT_MAPPER.readValue(
//                    claimsSet.getStringClaim("profile.authorities"), SimpleGrantedAuthority[].class);
//            profile.setAuthorities(CollectionUtils.arrayToList(simpleGrantedAuthorities));

            LocalDateTime creationTime = convertToLocalDateTime(claimsSet.getIssueTime());

            return new UserAuthenticationToken(claimsSet.getSubject(),
                    userDetails.getPassword(), true, creationTime);
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public String createIDToken(AuthorizationModel authorizationModel, String clientId,
                                Duration idTokenValidity, List<String> scope) {
        try {
            Profile profile = authorizationModel.getProfile();
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .subject(profile.getUsername())
                    .issuer(metadataService.findMetadata().getIssuer())
                    .audience(clientId)
                    .issueTime(new Date())
                    .expirationTime(convertToDate(authorizationModel.getLoginTime()
                            .plus(idTokenValidity)))
                    .claim("auth_time", convertToDate(authorizationModel.getLoginTime()))
                    .claim("nonce", authorizationModel.getNonce())
                    .claim("azp", clientId);
            if (scope.contains("profile")) {
                claimsSetBuilder.claim("given_name", profile.getFirstName())
                        .claim("family_name", profile.getLastName());
            }
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetBuilder.build());
            RSASSASigner signer = new RSASSASigner(cryptographyService.getApplicableSigningKey());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
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
