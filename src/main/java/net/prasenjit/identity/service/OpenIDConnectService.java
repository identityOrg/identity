package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.UserConsent;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.model.openid.OpenIDSessionContainer;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.UserConsentRepository;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OpenIDConnectService {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final OpenIDSessionContainer sessionContainer;
    private final CodeFactory codeFactory;

    public AuthorizationResponse processAuthentication(AuthorizationModel authorizationModel,
                                                       AuthenticationRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = ValidationUtils.extractPrincipal(authentication);

        // Check prompt and login status
        Prompt prompt = request.getPrompt();
        if (!prompt.isValid()) {
            return new AuthenticationErrorResponse(request.getRedirectionURI(),
                    OAuth2Error.INVALID_REQUEST.setDescription("Invalid prompt"),
                    request.getState(), request.getResponseMode());
        }
        if (principal == null) {
            if (prompt.contains(Prompt.Type.NONE)) {
                return new AuthenticationErrorResponse(request.getRedirectionURI(),
                        OIDCError.LOGIN_REQUIRED, request.getState(), request.getResponseMode());
            } else {
                return new IdentityViewResponse(IdentityViewResponse.ViewType.LOGIN);
            }
        }
        if (prompt.contains(Prompt.Type.LOGIN) && !sessionContainer.isInteractiveLoginDone()) {
            return new IdentityViewResponse(IdentityViewResponse.ViewType.LOGIN);
        }
        // End prompt and login status check

        Optional<Client> client = clientRepository.findById(request.getClientID().getValue());

        if (!client.isPresent()) {
            return new AuthorizationErrorResponse(request.getRedirectionURI(),
                    OAuth2Error.INVALID_CLIENT.setDescription(OAuthError.CLIENT_NOT_FOUND),
                    request.getState(), request.getResponseMode());
        } else {
            // Redirect URI validation start
            String[] redirectUris = client.get().getRedirectUris();
            if (!ArrayUtils.contains(redirectUris, request.getRedirectionURI().toString())) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(),
                        OAuth2Error.INVALID_REQUEST.setDescription(OAuthError.INVALID_REDIRECT_URI),
                        request.getState(), request.getResponseMode());
            }
            // Redirect URI validation end

            Scope filteredScope = ValidationUtils.filterScopeToMap(client.get().getApprovedScopes(),
                    request.getScope(), authorizationModel);

            if (ValidationUtils.invalidGrant(request, client.get())) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,
                        request.getState(), request.getResponseMode());
            }

            // if consent prompt is must
            if (prompt.contains(Prompt.Type.CONSENT)) {
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }
            // Check for already approved scopes
            Optional<UserConsent> consent = userConsentRepository.findById(new UserConsent.UserConsentPK(
                    principal.getUsername(), client.get().getClientId()));

            if (consent.isPresent()) {

                Scope savedConsentScope = Scope.parse(consent.get().getScopes());
                for (String s : filteredScope.toStringList()) {
                    if (!savedConsentScope.contains(s)) {
                        if (prompt.contains(Prompt.Type.NONE)) {
                            return new AuthenticationErrorResponse(request.getRedirectionURI(),
                                    OIDCError.INTERACTION_REQUIRED, request.getState(), request.getResponseMode());
                        }
                        return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
                    }
                }

                AuthorizationCode code = null;
                AccessToken accessToken = null;
                LocalDateTime loginTime = ((UserAuthenticationToken) authentication).getLoginTime();
                if (request.getResponseType().contains(ResponseType.Value.CODE)) {
                    net.prasenjit.identity.entity.AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(
                            client.get().getClientId(), request.getRedirectionURI().toString(),
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
                return new AuthorizationSuccessResponse(request.getRedirectionURI(), code, accessToken, request.getState(),
                        request.getResponseMode());
            } else {
                if (prompt.contains(Prompt.Type.NONE)) {
                    return new AuthenticationErrorResponse(request.getRedirectionURI(),
                            OIDCError.INTERACTION_REQUIRED, request.getState(), request.getResponseMode());
                }
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }
        }
    }
}
