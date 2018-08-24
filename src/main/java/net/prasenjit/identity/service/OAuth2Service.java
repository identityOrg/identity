package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.entity.UserConsent;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.*;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.basic.BasicAuthenticationToken;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final CodeFactory codeFactory;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final AuthorizationCodeRepository codeRepository;

    public AuthorizationResponse processAuthorization(ConsentModel consentModel,
                                                      AuthorizationRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = ValidationUtils.extractPrincipal(authentication);

        Optional<Client> client = clientRepository.findById(request.getClientID().getValue());

        if (!client.isPresent()) {
            if (request.getRedirectionURI() != null) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(),
                        OAuth2Error.INVALID_CLIENT.setDescription(OAuthError.CLIENT_NOT_FOUND),
                        request.getState(), request.getResponseMode());
            }
            return new IdentityViewResponse(OAuth2Error.INVALID_CLIENT);
        } else {
            URI redirectUri;
            consentModel.setClient(client.get());

            // Redirect URI validation start
            String[] redirectUris = client.get().getRedirectUris();
            if (request.getRedirectionURI() != null) {
                if (!ArrayUtils.contains(redirectUris, request.getRedirectionURI().toString())) {
                    return new AuthorizationErrorResponse(request.getRedirectionURI(),
                            OAuth2Error.INVALID_REQUEST.setDescription(OAuthError.INVALID_REDIRECT_URI),
                            request.getState(), request.getResponseMode());
                }
                redirectUri = request.getRedirectionURI();
            } else {
                redirectUri = URI.create(redirectUris[0]);
            }
            consentModel.setRedirectUriUsed(redirectUri);
            // Redirect URI validation end

            if (ValidationUtils.invalidGrant(request, client.get())) {
                return new AuthorizationErrorResponse(redirectUri, OAuth2Error.INVALID_GRANT, request.getState(),
                        request.getResponseMode());
            }

            if (consentModel.isConsentSubmitted()) {
                if (!consentModel.isValid()) {
                    return new AuthorizationErrorResponse(redirectUri, OAuth2Error.ACCESS_DENIED,
                            request.getState(), request.getResponseMode());
                } else {
                    Scope approvedScope = new Scope();
                    consentModel.getFilteredScopes().entrySet().stream().filter(Map.Entry::getValue)
                            .map(Map.Entry::getKey).forEach(approvedScope::add);

                    // Save consent
                    UserConsent userConsent = new UserConsent();
                    userConsent.setUsername(principal.getUsername());
                    userConsent.setClientID(client.get().getClientId());
                    userConsent.setApprovalDate(LocalDateTime.now());
                    userConsent.setScopes(approvedScope.toString());
                    userConsentRepository.save(userConsent);

                    return respondWithSuccess(request, (UserAuthenticationToken) authentication,
                            principal, client.get(), redirectUri, approvedScope);
                }
            }


            Scope filteredScope = ValidationUtils.filterScopeToMap(client.get().getApprovedScopes(),
                    request.getScope(), consentModel);

            // Check for already approved scopes
            Optional<UserConsent> consent = userConsentRepository.findById(new UserConsent.UserConsentPK(
                    principal.getUsername(), client.get().getClientId()));

            if (consent.isPresent()) {

                Scope savedConsentScope = Scope.parse(consent.get().getScopes());
                for (String s : filteredScope.toStringList()) {
                    if (!savedConsentScope.contains(s)) {
                        return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
                    }
                }

                return respondWithSuccess(request, (UserAuthenticationToken) authentication,
                        principal, client.get(), redirectUri, filteredScope);
            } else {
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }
        }
    }

    private AuthorizationResponse respondWithSuccess(AuthorizationRequest request,
                                                     UserAuthenticationToken authentication,
                                                     Profile principal, Client client,
                                                     URI redirectUri, Scope filteredScope) {
        AuthorizationCode code = null;
        AccessToken accessToken = null;
        LocalDateTime loginTime = authentication.getLoginTime();
        if (request.getResponseType().contains(ResponseType.Value.CODE)) {
            String value = request.getState() != null ? request.getState().getValue() : null;
            net.prasenjit.identity.entity.AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(
                    client.getClientId(), redirectUri.toString(),
                    filteredScope.toString(), principal.getUsername(), value,
                    Duration.ofMinutes(10), loginTime, false);
            code = new AuthorizationCode(authorizationCode.getAuthorizationCode());
        }
        if (request.getResponseType().contains(ResponseType.Value.TOKEN)) {
            net.prasenjit.identity.entity.AccessToken token = codeFactory.createAccessToken(principal,
                    client.getClientId(), client.getAccessTokenValidity(), filteredScope.toString(), loginTime);
            long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), token.getExpiryDate());
            accessToken = new BearerAccessToken(token.getAssessToken(), expIn, filteredScope);
        }
        return new AuthorizationSuccessResponse(redirectUri, code, accessToken, request.getState(),
                request.getResponseMode());
    }

    public URI getRedirectUriForClientId(String value) {
        Optional<Client> optionalClient = clientRepository.findById(value);
        if (optionalClient.isPresent()) {
            if (optionalClient.get().getRedirectUris() != null && optionalClient.get().getRedirectUris().length > 0) {
                return URI.create(optionalClient.get().getRedirectUris()[0]);
            }
        }
        return null;
    }

    public TokenResponse handleTokenRequest(TokenRequest tokenRequest) {
        Client client;
        if (tokenRequest.getClientAuthentication() == null) {
            ClientID clientId = tokenRequest.getClientID();
            Optional<Client> optionalClient = clientRepository.findById(clientId.getValue());
            if (optionalClient.isPresent()) {
                client = optionalClient.get();
                if (!StringUtils.hasText(client.getClientSecret())) {
                    return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED);
                }
            } else {
                return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED);
            }
        } else {
            ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
            String clientId = clientAuthentication.getClientID().getValue();
            String clientSecret;
            if (clientAuthentication.getMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
                clientSecret = ((ClientSecretBasic) clientAuthentication).getClientSecret().getValue();
            } else if (clientAuthentication.getMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
                clientSecret = ((ClientSecretPost) clientAuthentication).getClientSecret().getValue();
            } else {
                return new TokenErrorResponse(OAuth2Error.INVALID_CLIENT.setDescription("Client authentication not supported"));
            }

            BasicAuthenticationToken authenticate;
            try {
                authenticate = (BasicAuthenticationToken) authenticationManager.authenticate(
                        new BasicAuthenticationToken(clientId, clientSecret));
            } catch (AuthenticationException e) {
                return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.setDescription("Client authentication failed"));
            }

            Profile clientProfile = (Profile) authenticate.getPrincipal();
            client = clientRepository.getOne(clientProfile.getUsername());
        }
        if (tokenRequest.getAuthorizationGrant().getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return handleGrantInternal(client,
                    ((AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant()));
        } else if (tokenRequest.getAuthorizationGrant().getType().equals(GrantType.CLIENT_CREDENTIALS)) {
            return handleGrantInternal(client, tokenRequest);
        } else if (tokenRequest.getAuthorizationGrant().getType().equals(GrantType.PASSWORD)) {
            return handleGrantInternal(client, tokenRequest,
                    ((ResourceOwnerPasswordCredentialsGrant) tokenRequest.getAuthorizationGrant()));
        } else if (tokenRequest.getAuthorizationGrant().getType().equals(GrantType.REFRESH_TOKEN)) {
            return handleGrantInternal(client,
                    ((RefreshTokenGrant) tokenRequest.getAuthorizationGrant()));
        } else {
            return new TokenErrorResponse(OAuth2Error.INVALID_GRANT);
        }
    }

    private TokenResponse handleGrantInternal(Client client, RefreshTokenGrant grant) {
        Optional<RefreshToken> tokenOptional = refreshTokenRepository.findById(grant.getRefreshToken().getValue());
        if (tokenOptional.isPresent()) {
            if (tokenOptional.get().isValid()) {
                Optional<User> userOptional = userRepository.findById(tokenOptional.get().getUsername());
                if (userOptional.isPresent()) {
                    if (userOptional.get().isValid()) {
                        tokenOptional.get().setUsed(true);
                        Profile userProfile = Profile.create(userOptional.get());
                        net.prasenjit.identity.entity.AccessToken accessToken = codeFactory.createAccessToken(userProfile,
                                client.getClientId(), client.getAccessTokenValidity(), tokenOptional.get().getScope(),
                                tokenOptional.get().getLoginDate());
                        RefreshToken refreshToken1 = codeFactory.createRefreshToken(client.getClientId(),
                                userOptional.get().getUsername(), tokenOptional.get().getScope(),
                                tokenOptional.get().getLoginDate(), client.getRefreshTokenValidity(),
                                tokenOptional.get().isOpenId());

                        long lifetime = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
                        Scope approvedScope = Scope.parse(accessToken.getScope());
                        AccessToken at = new BearerAccessToken(accessToken.getAssessToken(), lifetime,
                                approvedScope);
                        com.nimbusds.oauth2.sdk.token.RefreshToken rt =
                                new com.nimbusds.oauth2.sdk.token.RefreshToken(refreshToken1.getRefreshToken());
                        if (tokenOptional.get().isOpenId()) {
                            String idToken = codeFactory.createIDToken(userProfile, tokenOptional.get().getLoginDate(), null,
                                    client.getClientId(), client.getAccessTokenValidity(), approvedScope.toStringList(),
                                    at.getValue(), null);
                            OIDCTokens tokens = new OIDCTokens(idToken, at, rt);
                            return new OIDCTokenResponse(tokens);
                        } else {
                            Tokens tokens = new Tokens(at, rt);
                            return new AccessTokenResponse(tokens);
                        }
                    } else {
                        return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid user"));
                    }
                } else {
                    return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Associated user not found"));
                }
            } else {
                return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Expired refresh token"));
            }
        }
        return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid refresh token"));
    }

    private TokenResponse handleGrantInternal(Client client, TokenRequest request,
                                              ResourceOwnerPasswordCredentialsGrant grant) {

        Authentication authToken = new UserAuthenticationToken(grant.getUsername(), grant.getPassword().getValue());
        try {
            authToken = authenticationManager.authenticate(authToken);
            Profile userProfile = (Profile) authToken.getPrincipal();
            Scope filteredScopes = ValidationUtils.filterScope(client.getApprovedScopes(), request.getScope());
            net.prasenjit.identity.entity.AccessToken accessToken = codeFactory.createAccessToken(userProfile,
                    client.getClientId(), client.getAccessTokenValidity(), filteredScopes.toString(), LocalDateTime.now());
            long lifetime = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
            AccessToken accessToken1 = new BearerAccessToken(accessToken.getAssessToken(), lifetime, filteredScopes);
            com.nimbusds.oauth2.sdk.token.RefreshToken refreshToken1 = null;
            if (!client.supportsGrant(net.prasenjit.identity.security.GrantType.REFRESH_TOKEN)) {
                RefreshToken refreshToken = codeFactory.createRefreshToken(client.getClientId(), userProfile.getUsername(),
                        filteredScopes.toString(), LocalDateTime.now(), client.getRefreshTokenValidity(), false);
                refreshToken1 = new com.nimbusds.oauth2.sdk.token.RefreshToken(refreshToken.getRefreshToken());
            }

            Tokens tokens = new Tokens(accessToken1, refreshToken1);
            return new AccessTokenResponse(tokens);
        } catch (BadCredentialsException e) {
            return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.setDescription("User authentication failed"));
        }
    }

    private TokenResponse handleGrantInternal(Client client, TokenRequest request) {
        Scope filteredScope = ValidationUtils.filterScope(client.getApprovedScopes(), request.getScope());
        net.prasenjit.identity.entity.AccessToken accessToken = codeFactory.createAccessToken(Profile.create(client), client.getClientId(),
                client.getAccessTokenValidity(), filteredScope.toString(), LocalDateTime.now());
        long lifetime = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        AccessToken accessToken1 = new BearerAccessToken(accessToken.getAssessToken(), lifetime, filteredScope);

        Tokens tokens = new Tokens(accessToken1, null);
        return new AccessTokenResponse(tokens);
    }

    private TokenResponse handleGrantInternal(Client client, AuthorizationCodeGrant grant) {
        Optional<net.prasenjit.identity.entity.AuthorizationCode> authorizationCode = codeRepository.findByAuthorizationCode(grant.getAuthorizationCode().getValue());
        if (authorizationCode.isPresent()) {
            if (!authorizationCode.get().isUsed()) {
                if (authorizationCode.get().getClientId().equals(client.getClientId())) {
                    if (!StringUtils.hasText(authorizationCode.get().getReturnUrl())
                            || (grant.getRedirectionURI() != null &&
                            authorizationCode.get().getReturnUrl().equals(grant.getRedirectionURI().toString()))) {
                        if (authorizationCode.get().isValid()) {
                            authorizationCode.get().setUsed(true);
                            Optional<User> associatedUser = userRepository.findById(authorizationCode.get().getUsername());
                            if (associatedUser.isPresent()) {
                                Scope approvedScope = Scope.parse(authorizationCode.get().getScope());
                                Profile userProfile = Profile.create(associatedUser.get());
                                com.nimbusds.oauth2.sdk.token.RefreshToken rt = null;
                                AccessToken at;

                                net.prasenjit.identity.entity.AccessToken accessToken = codeFactory.createAccessToken(
                                        userProfile, client.getClientId(), client.getAccessTokenValidity(),
                                        approvedScope.toString(), authorizationCode.get().getLoginDate());
                                long lifetime = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
                                at = new BearerAccessToken(accessToken.getAssessToken(), lifetime, approvedScope);


                                RefreshToken refreshToken;
                                if (client.supportsGrant(net.prasenjit.identity.security.GrantType.REFRESH_TOKEN)) {
                                    refreshToken = codeFactory.createRefreshToken(client.getClientId(),
                                            associatedUser.get().getUsername(),
                                            accessToken.getScope(), authorizationCode.get().getLoginDate(),
                                            client.getRefreshTokenValidity(), authorizationCode.get().isOpenId());
                                    rt = new com.nimbusds.oauth2.sdk.token.RefreshToken(refreshToken.getRefreshToken());
                                }

                                String idToken;
                                if (authorizationCode.get().isOpenId()) {
                                    idToken = codeFactory.createIDToken(userProfile,
                                            authorizationCode.get().getLoginDate(), null,
                                            client.getClientId(), client.getAccessTokenValidity(),
                                            approvedScope.toStringList(), accessToken.getAssessToken(),
                                            null);
                                    OIDCTokens tokens = new OIDCTokens(idToken, at, rt);
                                    return new OIDCTokenResponse(tokens);
                                } else {
                                    Tokens tokens = new Tokens(at, rt);
                                    return new AccessTokenResponse(tokens);
                                }
                            }
                            return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid user"));
                        }
                        return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Code expired"));
                    }
                    return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Redirect URI did not match"));
                }
                return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid code"));
            }
            return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Code used"));
        }
        return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid code"));
    }
}