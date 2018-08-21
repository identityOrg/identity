package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.UserConsent;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.UserConsentRepository;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OAuth2Service1 {

    private static final String CLIENT_NOT_FOUND = "Client not found";
    private static final String INVALID_REDIRECT_URI = "Invalid redirect URI";
    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final CodeFactory codeFactory;

    public AuthorizationResponse processAuthorization(AuthorizationModel authorizationModel, AuthorizationRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = extractPrincipal(authentication);

        Optional<Client> client = clientRepository.findById(request.getClientID().getValue());

        if (!client.isPresent()) {
            if (request.getRedirectionURI() != null) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(),
                        OAuth2Error.INVALID_CLIENT.setDescription(CLIENT_NOT_FOUND),
                        request.getState(), request.getResponseMode());
            }
            return new IdentityViewResponse(OAuth2Error.INVALID_CLIENT);
        } else {
            String[] redirectUris = client.get().getRedirectUris();
            URI redirectUri;

            // Redirect URI validation start
            if (request.getRedirectionURI() != null) {
                if (!ArrayUtils.contains(redirectUris, request.getRedirectionURI().toString())) {
                    return new AuthorizationErrorResponse(request.getRedirectionURI(),
                            OAuth2Error.INVALID_REQUEST.setDescription(INVALID_REDIRECT_URI),
                            request.getState(), request.getResponseMode());
                }
                redirectUri = request.getRedirectionURI();
            } else {
                redirectUri = URI.create(redirectUris[0]);
            }
            // Redirect URI validation end

            Scope filteredScope = filterScopeToMap(client.get().getApprovedScopes(), request.getScope(), authorizationModel);

            // Grant validation start
            net.prasenjit.identity.security.GrantType[] approvedGrants = client.get().getApprovedGrants();
            if (request.getResponseType().impliesCodeFlow()) {
                if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.IMPLICIT)) {
                    return new AuthorizationErrorResponse(redirectUri, OAuth2Error.INVALID_GRANT, request.getState(),
                            request.getResponseMode());
                }
            }
            if (request.getResponseType().impliesImplicitFlow()) {
                if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.AUTHORIZATION_CODE)) {
                    return new AuthorizationErrorResponse(redirectUri, OAuth2Error.INVALID_GRANT, request.getState(),
                            request.getResponseMode());
                }
            }
            if (request.getResponseType().impliesHybridFlow()) {
                if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.AUTHORIZATION_CODE)) {
                    return new AuthorizationErrorResponse(redirectUri, OAuth2Error.INVALID_GRANT, request.getState(),
                            request.getResponseMode());
                }
                if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.IMPLICIT)) {
                    return new AuthorizationErrorResponse(redirectUri, OAuth2Error.INVALID_GRANT, request.getState(),
                            request.getResponseMode());
                }
            }
            // Grant validation end

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

                AuthorizationCode code = null;
                AccessToken accessToken = null;
                LocalDateTime loginTime = ((UserAuthenticationToken) authentication).getLoginTime();
                if (request.getResponseType().contains(ResponseType.Value.CODE)) {
                    net.prasenjit.identity.entity.AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(client.get().getClientId(), redirectUri.toString(),
                            filteredScope.toString(), principal.getUsername(), request.getState().getValue(),
                            Duration.ofMinutes(10), loginTime, false);
                    code = new AuthorizationCode(authorizationCode.getAuthorizationCode());
                }
                if (request.getResponseType().contains(ResponseType.Value.TOKEN)) {
                    net.prasenjit.identity.entity.AccessToken token = codeFactory.createAccessToken(principal, client.get().getClientId(),
                            client.get().getAccessTokenValidity(), filteredScope.toString(), loginTime);
                    long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), token.getExpiryDate());
                    accessToken = new BearerAccessToken(token.getAssessToken(), expIn, filteredScope);
                }
                return new AuthorizationSuccessResponse(redirectUri, code, accessToken, request.getState(),
                        request.getResponseMode());
            } else {
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }
        }
    }

    private Scope filterScopeToMap(String approved, Scope requestedScope, AuthorizationModel authorizationModel) {
        if (approved == null) {
            return new Scope();
        }
        Scope approvedScopes = Scope.parse(approved);
        if (requestedScope == null) {
            authorizationModel.setFilteredScopes(approvedScopes.toStringList().stream()
                    .collect(Collectors.toMap(s -> s, s -> Boolean.TRUE)));
            return approvedScopes;
        }
        Scope filteredScopes = new Scope();
        for (String r : requestedScope.toStringList()) {
            if (approvedScopes.contains(r)) {
                authorizationModel.getFilteredScopes().put(r, Boolean.TRUE);
                filteredScopes.add(r);
            }
        }
        return filteredScopes;
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

    @SuppressWarnings("unchecked")
    private <T> T extractPrincipal(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (Profile.class.isInstance(principal)) {
                return (T) principal;
            }
        }
        return null;
    }

}
