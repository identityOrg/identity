package net.prasenjit.identity.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.scope.ScopeEntity;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.scope.ClaimEntity;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.ScopeRepository;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.security.bearer.BearerAuthenticationToken;
import net.prasenjit.identity.service.openid.CryptographyService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserInfoService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final ScopeRepository scopeRepository;
    private final CryptographyService cryptographyService;

    public UserInfoResponse retrieveUserInfo(UserInfoRequest request) {
        AccessToken accessToken = request.getAccessToken();
        if (accessToken == null) {
            return new UserInfoErrorResponse(BearerTokenError.MISSING_TOKEN);
        } else if (!(accessToken instanceof BearerAccessToken)) {
            return new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);
        }
        BearerAuthenticationToken authenticationToken = new BearerAuthenticationToken(null, accessToken.getValue());
        try {
            authenticationToken = (BearerAuthenticationToken) authenticationManager.authenticate(authenticationToken);

            Profile userProfile = (Profile) authenticationToken.getPrincipal();
            UserInfo claimsSet = new UserInfo(new Subject(userProfile.getUsername()));

            Optional<User> userOptional = userRepository.findById(userProfile.getUsername());
            if (userOptional.isPresent()) {
                UserInfo userInfo = userOptional.get().getUserInfo();
                for (Profile.SimpleGrantedAuthority authority : userProfile.getAuthorities()) {
                    Optional<ScopeEntity> optionalScope = scopeRepository.findById(authority.getAuthority());
                    if (optionalScope.isPresent()) {
                        ScopeEntity scope = optionalScope.get();
                        for (ClaimEntity claimEntity : scope.getClaims()) {
                            if (StringUtils.hasText(claimEntity.getStandardAttribute())) {
                                claimsSet.setClaim(claimEntity.getStandardAttribute(),
                                        userInfo.getClaim(claimEntity.getStandardAttribute()));
                            }
                        }
                    }
                }
            }
            return createSuccessResponse(userProfile, claimsSet);
        } catch (AuthenticationException e) {
            return new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);
        }
    }

    private UserInfoResponse createSuccessResponse(Profile userProfile, UserInfo userInfo) {
        Optional<Client> clientOptional = clientRepository.findById(userProfile.getAssociatedClient());
        if (clientOptional.isPresent()) {
            OIDCClientMetadata metadata = clientOptional.get().getMetadata();
            JWT jwt = null;
            if (metadata.getUserInfoJWSAlg() != null) {
                JWKSet keySet = cryptographyService.loadJwkKeys();
                JWK signingKey = keySet.getKeyByKeyId("jwk-sig");
                JWSHeader header = new JWSHeader.Builder(metadata.getUserInfoJWSAlg())
                        .keyID(signingKey.getKeyID()).build();
                try {
                    SignedJWT signedJWT = new SignedJWT(header, userInfo.toJWTClaimsSet());

                    RSASSASigner signer = new RSASSASigner((RSAKey) signingKey);
                    signedJWT.sign(signer);
                    jwt = signedJWT;

                    if (metadata.getUserInfoJWEAlg() != null && metadata.getUserInfoJWEEnc() != null) {
                        JWK encryptionKey = keySet.getKeyByKeyId("jwk-enc");
                        RSAEncrypter encrypter = new RSAEncrypter((RSAKey) encryptionKey);
                        JWEObject jweObject = new JWEObject(
                                new JWEHeader.Builder(metadata.getUserInfoJWEAlg(), metadata.getUserInfoJWEEnc())
                                        .contentType("JWT")
                                        .keyID(encryptionKey.getKeyID())
                                        .build(),
                                new Payload(signedJWT));
                        jweObject.encrypt(encrypter);
                        jwt = JWTParser.parse(jweObject.serialize());
                    }
                } catch (ParseException e) {
                    log.debug("Unexpected parse exception", e);
                    return new UserInfoErrorResponse(e.getErrorObject());
                } catch (JOSEException | java.text.ParseException e) {
                    log.error("JWT error", e);
                    return new UserInfoErrorResponse(OAuth2Error.SERVER_ERROR.appendDescription(": " + e.getMessage()));
                }
            }
            if (metadata.getUserInfoJWEAlg() != null && metadata.getUserInfoJWEEnc() != null) {
                JWKSet keySet = cryptographyService.loadJwkKeys();
                JWK encryptionKey = keySet.getKeyByKeyId("jwk-enc");
                try {
                    RSAEncrypter encrypter = new RSAEncrypter((RSAKey) encryptionKey);
                    EncryptedJWT encryptedJWT = new EncryptedJWT(
                            new JWEHeader.Builder(metadata.getUserInfoJWEAlg(), metadata.getUserInfoJWEEnc())
                                    .contentType("JWT")
                                    .keyID(encryptionKey.getKeyID())
                                    .build(),
                            userInfo.toJWTClaimsSet());
                    encryptedJWT.encrypt(encrypter);
                    jwt = encryptedJWT;
                } catch (JOSEException e) {
                    log.error("JWT error", e);
                    return new UserInfoErrorResponse(OAuth2Error.SERVER_ERROR.appendDescription(": " + e.getMessage()));
                } catch (ParseException e) {
                    log.debug("Unexpected parse exception", e);
                    return new UserInfoErrorResponse(e.getErrorObject());
                }
            }
            if (jwt != null) {
                return new UserInfoSuccessResponse(jwt);
            }
        }
        return new UserInfoSuccessResponse(userInfo);
    }

}
