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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.ResolveException;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.user.UserConsent;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.model.openid.OpenIDSessionContainer;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.UserConsentRepository;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.openid.JWTResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OpenIDConnectService {

    private final ClientRepository clientRepository;
    private final UserConsentRepository userConsentRepository;
    private final OpenIDSessionContainer sessionContainer;
    private final CodeFactory codeFactory;
    private final JWTResolver jwtResolver;

    @Transactional
    public AuthorizationResponse processAuthentication(ConsentModel consentModel,
                                                       AuthenticationRequest request)
            throws ParseException, ResolveException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Profile principal = ValidationUtils.extractPrincipal(authentication);

        Optional<Client> client = clientRepository.findById(request.getClientID().getValue());

        if (!client.isPresent()) {
            return new AuthorizationErrorResponse(request.getRedirectionURI(),
                    OAuth2Error.INVALID_CLIENT, request.getState(), request.getResponseMode());
        } else {
            request = jwtResolver.resolveAuthenticationRequest(request, client.get());
            OIDCClientMetadata clientMetadata = client.get().getMetadata();

            // handle login hint
            IdentityViewResponse identityLoginView = new IdentityViewResponse(IdentityViewResponse.ViewType.LOGIN);
            if (StringUtils.hasText(request.getLoginHint())) {
                String loginHint = request.getLoginHint();
                if (principal != null && !loginHint.equals(principal.getUsername())) {
                    return new AuthenticationErrorResponse(request.getRedirectionURI(),
                            OIDCError.LOGIN_REQUIRED.appendDescription(" :Mismatch with login_hint"),
                            request.getState(), request.getResponseMode());
                }
                identityLoginView.getAttributes().put("loginHint", loginHint);
            }
            // TODO handle id token hint


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
                    return identityLoginView;
                }
            } else {
                // max age check
                if (request.getMaxAge() > 0 || clientMetadata.getDefaultMaxAge() > 0) {
                    int maxAge = request.getMaxAge() > 0 ? request.getMaxAge() : clientMetadata.getDefaultMaxAge();
                    LocalDateTime loginTime = ((UserAuthenticationToken) authentication).getLoginTime();
                    if (loginTime.plusSeconds(maxAge).isBefore(LocalDateTime.now())) {
                        if (prompt.contains(Prompt.Type.NONE)) {
                            return new AuthenticationErrorResponse(request.getRedirectionURI(), OIDCError.LOGIN_REQUIRED,
                                    request.getState(), request.getResponseMode());
                        } else {
                            return identityLoginView;
                        }
                    }
                }
            }
            if (prompt.contains(Prompt.Type.LOGIN) && !sessionContainer.isInteractiveLoginDone()) {
                return identityLoginView;
            }
            // End prompt and login status check
            consentModel.setClient(client.get());
            // Redirect URI validation start
            if (clientMetadata.getRedirectionURIStrings() != null) {
                if (!clientMetadata.getRedirectionURIStrings().contains(request.getRedirectionURI().toString())) {
                    return new AuthorizationErrorResponse(request.getRedirectionURI(),
                            OAuth2Error.INVALID_REQUEST.setDescription("Invalid redirect URI"),
                            request.getState(), request.getResponseMode());
                }
            }
            // Redirect URI validation end

            Scope filteredScope = ValidationUtils.filterScopeToMap(client.get().getApprovedScopes(),
                    request.getScope(), consentModel);

            if (ValidationUtils.invalidGrant(request, client.get())) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,
                        request.getState(), request.getResponseMode());
            }

            // response type validation
            ResponseType responseType = request.getResponseType();
            if (!clientMetadata.getResponseTypes().contains(responseType)) {
                return new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.UNSUPPORTED_RESPONSE_TYPE,
                        request.getState(), request.getResponseMode());
            }

            // if consent prompt is must
            if (prompt.contains(Prompt.Type.CONSENT) && !consentModel.isConsentSubmitted()) {
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

            // Check for already approved consent
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

        LocalDateTime loginTime = authentication.getLoginTime();
        if (request.getResponseType().contains(ResponseType.Value.CODE)) {
            code = codeFactory.createAuthorizationCode(request, request.getRedirectionURI(), principal.getUsername(),
                    filteredScope, Duration.ofMinutes(10), loginTime, true);
        }
        BearerAccessToken accessToken = null;
        if (request.getResponseType().contains(ResponseType.Value.TOKEN)) {
            accessToken = codeFactory.createAccessToken(principal, request.getClientID(),
                    client.getAccessTokenValidity(), filteredScope, loginTime, null);
        }
        JWT idToken = null;
        if (request.getResponseType().contains("id_token")) {
            idToken = codeFactory.createIDToken(principal, loginTime, request.getNonce(),
                    request.getClientID(), client.getAccessTokenValidity(), filteredScope, accessToken, code);
        }
        return new AuthenticationSuccessResponse(request.getRedirectionURI(), code, idToken, accessToken,
                request.getState(), null, request.getResponseMode());
    }
}
