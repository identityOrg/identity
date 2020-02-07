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

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AccessTokenEntity;
import net.prasenjit.identity.entity.AuthorizationCodeEntity;
import net.prasenjit.identity.entity.RefreshTokenEntity;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.entity.user.UserConsent;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.*;
import net.prasenjit.identity.security.basic.BasicAuthenticationToken;
import net.prasenjit.identity.security.jwt.JWTClientAuthenticationToken;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.openid.MetadataService;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class OAuth2Service {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final CodeFactory codeFactory;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final UserRepository userRepository;
    private final AuthorizationCodeRepository codeRepository;
    private final MetadataService metadataService;

    @Transactional
    public AuthorizationResponse processAuthorization(ConsentModel consentModel,
                                                      AuthorizationRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = ValidationUtils.extractPrincipal(authentication);

        Optional<Client> client = clientRepository.findById(request.getClientID().getValue());

        if (client.isEmpty()) {
            if (request.getRedirectionURI() != null) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(),
                        OAuth2Error.INVALID_CLIENT, request.getState(), request.getResponseMode());
            }
            return new IdentityViewResponse(OAuth2Error.INVALID_CLIENT);
        } else {
            URI redirectUri;
            consentModel.setClient(client.get());

            // Redirect URI validation start
            Set<String> redirectUris = client.get().getMetadata().getRedirectionURIStrings();
            if (!CollectionUtils.isEmpty(redirectUris)) {
                if (request.getRedirectionURI() != null) {
                    if (!redirectUris.contains(request.getRedirectionURI().toString())) {
                        return new AuthorizationErrorResponse(request.getRedirectionURI(),
                                OAuth2Error.INVALID_REQUEST.setDescription("Invalid redirect URI"),
                                request.getState(), request.getResponseMode());
                    }
                    redirectUri = request.getRedirectionURI();
                } else {
                    redirectUri = client.get().getMetadata().getRedirectionURI();
                }
            } else {
                return new IdentityViewResponse(OAuth2Error.INVALID_REQUEST.setDescription("Redirect URI must be provided"));
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
            code = codeFactory.createAuthorizationCode(request, request.getRedirectionURI(), principal.getUsername(),
                    filteredScope, Duration.ofMinutes(10), loginTime, false);
        }
        if (request.getResponseType().contains(ResponseType.Value.TOKEN)) {
            accessToken = codeFactory.createAccessToken(principal,
                    request.getClientID(), client.getAccessTokenValidity(), filteredScope, loginTime, null);
        }
        return new AuthorizationSuccessResponse(redirectUri, code, accessToken, request.getState(),
                request.getResponseMode());
    }

    public URI getRedirectUriForClientId(ClientID clientID) {
        Optional<Client> optionalClient = clientRepository.findById(clientID.getValue());
        return optionalClient.map(client -> client.getMetadata().getRedirectionURI()).orElse(null);
    }

    @Transactional
    public TokenResponse handleTokenRequest(TokenRequest tokenRequest) {
        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
        ClientID clientID = tokenRequest.getClientID();
        if (clientID == null && clientAuthentication != null) {
            clientID = clientAuthentication.getClientID();
        }
        if (clientID == null) {
            return new TokenErrorResponse(OAuth2Error.INVALID_CLIENT);
        }
        Client client = clientRepository.findById(clientID.getValue()).orElse(null);
        if (client == null || !client.isAccountNonExpired()) {
            return new TokenErrorResponse(OAuth2Error.INVALID_CLIENT);
        }
        ErrorObject errorObject = authenticateClient(clientAuthentication, clientID, client);
        if (errorObject != null) {
            return new TokenErrorResponse(errorObject);
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

    private ErrorObject authenticateClient(ClientAuthentication clientAuthentication, ClientID clientID, Client client) {
        if (clientAuthentication == null) {
            if (StringUtils.hasText(client.getClientSecret())) {
                return OAuth2Error.ACCESS_DENIED;
            }
        } else {
            AbstractAuthenticationToken authToken;
            ClientAuthenticationMethod registeredAuthMethod = client.getMetadata().getTokenEndpointAuthMethod();
            ClientAuthenticationMethod usedAuthMethod = clientAuthentication.getMethod();
            if (metadataService.findOIDCConfiguration().getTokenEndpointAuthMethods().contains(usedAuthMethod) &&
                    (registeredAuthMethod == null || registeredAuthMethod.equals(usedAuthMethod))) {
                if (clientAuthentication instanceof PlainClientSecret) {
                    authToken = new BasicAuthenticationToken(clientID, ((PlainClientSecret) clientAuthentication).getClientSecret());
                } else if (clientAuthentication instanceof JWTAuthentication) {
                    authToken = new JWTClientAuthenticationToken(clientAuthentication.getClientID(), clientAuthentication);
                } else {
                    return OAuth2Error.ACCESS_DENIED.setDescription("Client authentication not supported");
                }
            } else {
                return OAuth2Error.ACCESS_DENIED.setDescription("Client authentication not supported");
            }

            try {
                authenticationManager.authenticate(authToken);
            } catch (AuthenticationException e) {
                return OAuth2Error.ACCESS_DENIED.setDescription("Client authentication failed");
            }
        }
        return null;
    }

    @Transactional(readOnly = true)
    public TokenIntrospectionResponse introspectToken(TokenIntrospectionRequest introspectionRequest) {
        ClientAuthentication clientAuthentication = introspectionRequest.getClientAuthentication();
        if (clientAuthentication == null) {
            return new TokenIntrospectionErrorResponse(OAuth2Error.INVALID_CLIENT);
        }
        ClientID clientID = clientAuthentication.getClientID();
        Client client = clientRepository.findById(clientID.getValue()).orElse(null);
        if (client == null || !client.isAccountNonExpired()) {
            return new TokenIntrospectionErrorResponse(OAuth2Error.INVALID_CLIENT);
        }
        ErrorObject errorObject = authenticateClient(clientAuthentication, clientID, client);
        if (errorObject != null) {
            return new TokenIntrospectionErrorResponse(errorObject);
        }

        Token token = introspectionRequest.getToken();
        Optional<AccessTokenEntity> accessToken = accessTokenRepository.findById(token.getValue());
        if (accessToken.isPresent()
                && accessToken.get().getClientId().equals(clientID.getValue())
                && accessToken.get().isValid()) {
            Profile userProfile = accessToken.get().getUserProfile();
            Optional<User> optionalUser = userRepository.findById(userProfile.getUsername());
            if (optionalUser.isPresent() && optionalUser.get().isValid()) {
                return new TokenIntrospectionSuccessResponse.Builder(true)
                        .clientID(clientID)
                        .issuer(metadataService.getIssuer())
                        .username(userProfile.getUsername())
                        .scope(Scope.parse(accessToken.get().getScope()))
                        .tokenType(AccessTokenType.BEARER)
                        .expirationTime(ValidationUtils.convertToDate(accessToken.get().getExpiryDate()))
                        .issueTime(ValidationUtils.convertToDate(accessToken.get().getCreationDate()))
                        .subject(new Subject(userProfile.getUsername()))
                        .audience(Collections.singletonList(new Audience(clientID.getValue())))
                        .build();
            }
        }
        Optional<RefreshTokenEntity> refreshToken = refreshTokenRepository.findById(token.getValue());
        if (refreshToken.isPresent()) {
            if (refreshToken.get().isValid() &&
                    refreshToken.get().getClientId().equals(clientID.getValue())) {
                String username = refreshToken.get().getUsername();
                Optional<User> optionalUser = userRepository.findById(username);
                if (optionalUser.isPresent() && optionalUser.get().isValid()) {
                    Profile userProfile = Profile.create(optionalUser.get());
                    return new TokenIntrospectionSuccessResponse.Builder(true)
                            .clientID(clientID)
                            .issuer(metadataService.getIssuer())
                            .username(userProfile.getUsername())
                            .scope(Scope.parse(refreshToken.get().getScope()))
                            .expirationTime(ValidationUtils.convertToDate(refreshToken.get().getExpiryDate()))
                            .issueTime(ValidationUtils.convertToDate(refreshToken.get().getCreationDate()))
                            .subject(new Subject(userProfile.getUsername()))
                            .audience(Collections.singletonList(new Audience(clientID.getValue())))
                            .build();
                }
            }
        }
        return new TokenIntrospectionSuccessResponse.Builder(false).build();
    }

    @Transactional
    public ErrorObject revokeToken(TokenRevocationRequest revocationRequest) {
        ClientAuthentication clientAuthentication = revocationRequest.getClientAuthentication();
        if (clientAuthentication == null) {
            return OAuth2Error.INVALID_CLIENT;
        }
        ClientID clientID = clientAuthentication.getClientID();
        Client client = clientRepository.findById(clientID.getValue()).orElse(null);
        if (client == null || !client.isAccountNonExpired()) {
            return OAuth2Error.INVALID_CLIENT;
        }
        ErrorObject errorObject = authenticateClient(clientAuthentication, clientID, client);
        if (errorObject != null) {
            return errorObject;
        }

        Token token = revocationRequest.getToken();
        Optional<AccessTokenEntity> accessToken = accessTokenRepository.findById(token.getValue());
        accessToken.filter(t -> t.getClientId().equals(clientID.getValue()))
                .ifPresent(t -> t.setActive(false));

        refreshTokenRepository.findById(token.getValue())
                .ifPresent(r -> revokeRefreshTokenRecursive(clientID, r));
        return null;
    }

    private void revokeRefreshTokenRecursive(final ClientID clientID, RefreshTokenEntity token) {
        token.setActive(false);
        accessTokenRepository.findByActiveTrueAndRefreshTokenEquals(token.getRefreshToken())
                .filter(t -> t.getClientId().equals(clientID.getValue()))
                .forEach(a -> a.setActive(false));
        refreshTokenRepository.findByActiveTrueAndParentRefreshTokenEquals(token.getRefreshToken())
                .filter(t -> t.getClientId().equals(clientID.getValue()))
                .forEach(r -> revokeRefreshTokenRecursive(clientID, r));

    }

    private TokenResponse handleGrantInternal(Client client, RefreshTokenGrant grant) {

        if (!client.supportsGrant(GrantType.REFRESH_TOKEN)) {
            return new TokenErrorResponse(OAuth2Error.INVALID_GRANT
                    .setDescription("Client doesn't support requested grant"));
        }
        Optional<RefreshTokenEntity> tokenOptional = refreshTokenRepository.findById(grant.getRefreshToken().getValue());
        if (tokenOptional.isPresent()) {
            if (tokenOptional.get().isValid()) {
                Optional<User> userOptional = userRepository.findById(tokenOptional.get().getUsername());
                if (userOptional.isPresent()) {
                    if (userOptional.get().isValid()) {
                        tokenOptional.get().setUsed(true);
                        Profile userProfile = Profile.create(userOptional.get());
                        ClientID clientId = new ClientID(client.getClientId());
                        Scope scope = Scope.parse(tokenOptional.get().getScope());
                        BearerAccessToken accessToken = codeFactory.createAccessToken(userProfile,
                                clientId, client.getAccessTokenValidity(), scope,
                                tokenOptional.get().getLoginDate(), tokenOptional.get().getRefreshToken());
                        RefreshToken refreshToken = codeFactory.createRefreshToken(clientId,
                                userOptional.get().getUsername(), scope,
                                tokenOptional.get().getLoginDate(), client.getRefreshTokenValidity(),
                                tokenOptional.get().isOpenId(), tokenOptional.get().getRefreshToken());

                        if (tokenOptional.get().isOpenId()) {
                            JWT idToken = codeFactory.createIDToken(userProfile, tokenOptional.get().getLoginDate(),
                                    null, clientId, client.getAccessTokenValidity(), accessToken.getScope(),
                                    accessToken, null);
                            OIDCTokens tokens = new OIDCTokens(idToken, accessToken, refreshToken);
                            return new OIDCTokenResponse(tokens);
                        } else {
                            Tokens tokens = new Tokens(accessToken, refreshToken);
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

        if (!client.supportsGrant(GrantType.PASSWORD)) {
            return new TokenErrorResponse(OAuth2Error.INVALID_GRANT
                    .setDescription("Client doesn't support requested grant"));
        }

        Authentication authToken = new UserAuthenticationToken(grant.getUsername(), grant.getPassword().getValue());
        try {
            authToken = authenticationManager.authenticate(authToken);
            Profile userProfile = (Profile) authToken.getPrincipal();
            Scope filteredScopes = ValidationUtils.filterScope(client.getApprovedScopes(), request.getScope());
            ClientID clientId = new ClientID(client.getClientId());
            BearerAccessToken accessToken = codeFactory.createAccessToken(userProfile,
                    clientId, client.getAccessTokenValidity(), filteredScopes, LocalDateTime.now(), null);

            RefreshToken refreshToken = null;
            if (client.supportsGrant(GrantType.REFRESH_TOKEN)) {
                refreshToken = codeFactory.createRefreshToken(clientId, userProfile.getUsername(),
                        filteredScopes, LocalDateTime.now(), client.getRefreshTokenValidity(), false, null);
            }

            Tokens tokens = new Tokens(accessToken, refreshToken);
            return new AccessTokenResponse(tokens);
        } catch (BadCredentialsException e) {
            return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.setDescription("User authentication failed"));
        }
    }

    private TokenResponse handleGrantInternal(Client client, TokenRequest request) {

        if (!client.supportsGrant(GrantType.CLIENT_CREDENTIALS)) {
            return new TokenErrorResponse(OAuth2Error.INVALID_GRANT
                    .setDescription("Client doesn't support requested grant"));
        }
        Scope filteredScope = ValidationUtils.filterScope(client.getApprovedScopes(), request.getScope());
        ClientID clientId = new ClientID(client.getClientId());
        BearerAccessToken accessToken = codeFactory.createAccessToken(Profile.create(client), clientId,
                client.getAccessTokenValidity(), filteredScope, LocalDateTime.now(), null);

        Tokens tokens = new Tokens(accessToken, null);
        return new AccessTokenResponse(tokens);
    }

    private TokenResponse handleGrantInternal(Client client, AuthorizationCodeGrant grant) {
        Optional<AuthorizationCodeEntity> authorizationCode = codeRepository.findByAuthorizationCode(grant.getAuthorizationCode().getValue());
        if (authorizationCode.isPresent()) {
            AuthorizationCodeEntity authCode = authorizationCode.get();
            if (!authCode.isUsed()) {
                ClientID clientId = new ClientID(client.getClientId());
                if (clientId.equals(authCode.getRequest().getClientID())) {
                    if (!StringUtils.hasText(authCode.getReturnUrl()) || (grant.getRedirectionURI() != null &&
                            authCode.getReturnUrl().equals(grant.getRedirectionURI().toString()))) {
                        if (authCode.isValid()) {
                            if (authCode.isChallengeAvailable()) {
                                if (grant.getCodeVerifier() != null) {
                                    CodeChallengeMethod method = authCode.getRequest().getCodeChallengeMethod();
                                    CodeChallenge compute = CodeChallenge.compute(method, grant.getCodeVerifier());
                                    if (!compute.equals(authCode.getRequest().getCodeChallenge())) {
                                        return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Invalid challenge"));
                                    }
                                }
                                return new TokenErrorResponse(OAuth2Error.ACCESS_DENIED.appendDescription(": Challenge required"));
                            }
                            authCode.setUsed(true);
                            Optional<User> associatedUser = userRepository.findById(authCode.getUsername());
                            if (associatedUser.isPresent()) {
                                Scope approvedScope = Scope.parse(authCode.getScope());
                                Profile userProfile = Profile.create(associatedUser.get());

                                BearerAccessToken accessToken = codeFactory.createAccessToken(
                                        userProfile, clientId, client.getAccessTokenValidity(),
                                        approvedScope, authCode.getLoginDate(), null);


                                RefreshToken refreshToken = null;
                                if (authCode.getRequest().getScope().contains("offline_access")
                                        && client.supportsGrant(GrantType.REFRESH_TOKEN)) {
                                    refreshToken = codeFactory.createRefreshToken(clientId,
                                            associatedUser.get().getUsername(),
                                            accessToken.getScope(), authCode.getLoginDate(),
                                            client.getRefreshTokenValidity(), authCode.isOpenId(), null);
                                }

                                JWT idToken;
                                if (authCode.isOpenId()) {
                                    AuthenticationRequest authenticationRequest = (AuthenticationRequest) authCode.getRequest();
                                    Nonce nonce = authenticationRequest.getNonce();
                                    idToken = codeFactory.createIDToken(userProfile, authCode.getLoginDate(),
                                            nonce, clientId, client.getAccessTokenValidity(), approvedScope,
                                            accessToken, null);
                                    OIDCTokens tokens = new OIDCTokens(idToken, accessToken, refreshToken);
                                    return new OIDCTokenResponse(tokens);
                                } else {
                                    Tokens tokens = new Tokens(accessToken, refreshToken);
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