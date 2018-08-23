package net.prasenjit.identity.service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.UserConsent;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.ConsentModel;
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

import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OpenIDConnectService {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final OpenIDSessionContainer sessionContainer;
    private final CodeFactory codeFactory;

    public AuthorizationResponse processAuthentication(ConsentModel consentModel,
                                                       AuthenticationRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = ValidationUtils.extractPrincipal(authentication);

        // Check prompt and login status
        Prompt prompt = request.getPrompt();
        if (prompt == null) prompt = new Prompt();
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
        } else {
            // max age check
            if (request.getMaxAge() > 0) {
                LocalDateTime loginTime = ((UserAuthenticationToken) authentication).getLoginTime();
                if (loginTime.plusSeconds(request.getMaxAge()).isBefore(LocalDateTime.now())) {
                    if (prompt.contains(Prompt.Type.NONE)) {
                        return new AuthenticationErrorResponse(request.getRedirectionURI(), OIDCError.LOGIN_REQUIRED,
                                request.getState(), request.getResponseMode());
                    } else {
                        return new IdentityViewResponse(IdentityViewResponse.ViewType.LOGIN);
                    }
                }
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
            consentModel.setClient(client.get());
            // Redirect URI validation start
            String[] redirectUris = client.get().getRedirectUris();
            if (!ArrayUtils.contains(redirectUris, request.getRedirectionURI().toString())) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(),
                        OAuth2Error.INVALID_REQUEST.setDescription(OAuthError.INVALID_REDIRECT_URI),
                        request.getState(), request.getResponseMode());
            }
            // Redirect URI validation end

            Scope filteredScope = ValidationUtils.filterScopeToMap(client.get().getApprovedScopes(),
                    request.getScope(), consentModel);

            if (ValidationUtils.invalidGrant(request, client.get())) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,
                        request.getState(), request.getResponseMode());
            }

            // if consent prompt is must
            if (prompt.contains(Prompt.Type.CONSENT)) {
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }

            // handle consent submission
            if (consentModel.isConsentSubmitted()) {
                if (!consentModel.isValid()) {
                    return new AuthenticationErrorResponse(request.getRedirectionURI(), OAuth2Error.ACCESS_DENIED,
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
                            principal, client.get(), approvedScope);
                }
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

                return respondWithSuccess(request, (UserAuthenticationToken) authentication, principal,
                        client.get(), filteredScope);
            } else {
                if (prompt.contains(Prompt.Type.NONE)) {
                    return new AuthenticationErrorResponse(request.getRedirectionURI(),
                            OIDCError.INTERACTION_REQUIRED, request.getState(), request.getResponseMode());
                }
                return new IdentityViewResponse(IdentityViewResponse.ViewType.CONSENT);
            }
        }
    }

    private AuthorizationResponse respondWithSuccess(AuthenticationRequest request,
                                                     UserAuthenticationToken authentication, Profile principal,
                                                     Client client, Scope filteredScope) {
        AuthorizationCode code = null;
        AccessToken accessToken = null;
        JWT idToken = null;

        LocalDateTime loginTime = authentication.getLoginTime();
        if (request.getResponseType().contains(ResponseType.Value.CODE)) {
            String stateValue = request.getState() == null ? null : request.getState().getValue();
            net.prasenjit.identity.entity.AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(
                    client.getClientId(), request.getRedirectionURI().toString(),
                    filteredScope.toString(), principal.getUsername(), stateValue,
                    Duration.ofMinutes(10), loginTime, false);
            code = new AuthorizationCode(authorizationCode.getAuthorizationCode());
        }
        if (request.getResponseType().contains(ResponseType.Value.TOKEN)) {
            net.prasenjit.identity.entity.AccessToken token = codeFactory.createAccessToken(principal, client.getClientId(),
                    client.getAccessTokenValidity(), filteredScope.toString(), loginTime);
            long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), token.getExpiryDate());
            accessToken = new BearerAccessToken(token.getAssessToken(), expIn, filteredScope);
        }
        if (request.getResponseType().contains("id_token")) {
            String at = accessToken == null ? null : accessToken.getValue();
            String ac = code == null ? null : code.getValue();
            String token = codeFactory.createIDToken(principal, loginTime, request.getNonce().getValue(),
                    client.getClientId(), client.getAccessTokenValidity(), filteredScope.toStringList(), at, ac);
            try {
                idToken = JWTParser.parse(token);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }
        return new AuthenticationSuccessResponse(request.getRedirectionURI(), code, idToken, accessToken,
                request.getState(), null, request.getResponseMode());
    }
}
