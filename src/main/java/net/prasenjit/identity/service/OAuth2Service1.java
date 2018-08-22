package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.UserConsent;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.UserConsentRepository;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuth2Service1 {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final CodeFactory codeFactory;

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
}