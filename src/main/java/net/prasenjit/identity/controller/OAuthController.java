package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.exception.UnauthenticatedClientException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.model.openid.core.AuthorizeRequest;
import net.prasenjit.identity.oauth.OAuthError;
import net.prasenjit.identity.service.OAuth2Service;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Controller
@RequestMapping("oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;

    @PostMapping(value = "token", params = "grant_type=password")
    @ResponseBody
    public OAuthToken passwordGrantToken(@RequestParam(value = "username") String username,
                                         @RequestParam(value = "password") String password,
                                         @RequestParam(value = "scope", defaultValue = "") String scope,
                                         Authentication clientAuth) {
        log.info("Processing password grant");
        Client client = extractPrincipal(clientAuth, Client.class);
        if (client != null) {
            return oAuth2Service.processPasswordGrant(client, username, password, scope);
        } else {
            throw new UnauthenticatedClientException("unauthorized_client", "client not authenticated");
        }
    }

    @PostMapping(value = "token", params = "grant_type=client_credentials")
    @ResponseBody
    public OAuthToken clientCredentialGrantToken(@RequestParam(value = "scope", defaultValue = "") String scope,
                                                 Authentication clientAuth) {
        log.info("Processing password grant");
        Client client = extractPrincipal(clientAuth, Client.class);
        if (client != null) {
            return oAuth2Service.processClientCredentialsGrant(client, scope);
        } else {
            throw new UnauthenticatedClientException("unauthorized_client", "client not authenticated");
        }
    }

    @PostMapping(value = "token", params = "grant_type=authorization_code")
    @ResponseBody
    public OAuthToken authorizationCodeGrantToken(@RequestParam(value = "code", required = false) String code,
                                                  @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                                  @RequestParam(value = "client_id", required = false) String clientId,
                                                  Authentication authentication) {
        log.info("Processing password grant");
        Client client = extractPrincipal(authentication, Client.class);
        return oAuth2Service.processAuthorizationCodeGrantToken(client, code, redirectUri, clientId);
    }

    @PostMapping(value = "token", params = "grant_type=refresh_token")
    @ResponseBody
    public OAuthToken refreshTokenGrantToken(
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            Authentication authentication) {
        log.info("Processing refresh token grant");
        Client client = extractPrincipal(authentication, Client.class);
        return oAuth2Service.processRefreshTokenGrantToken(client, refreshToken);
    }

    @GetMapping("authorize")
    public String oAuthAuthorize(AuthorizeRequest request, Authentication authentication, Model model) {
        log.info("Processing authorization code grant");
        AuthorizationModel authorizationModel = oAuth2Service.validateAuthorizationGrant(authentication, request);
        if (authorizationModel.isValid()) {
            model.addAttribute("model", authorizationModel);
            return "authorize";
        } else {
            return buildErrorUrl(authorizationModel);
        }
    }

    @PostMapping("authorize")
    public String submitAuthorize(@ModelAttribute AuthorizationModel authorizationModel,
                                  Authentication authentication) {
        User user = extractPrincipal(authentication, User.class);
        authorizationModel.setUser(user);
        authorizationModel = oAuth2Service.processAuthorizationOrImplicitGrant(authorizationModel);
        if (authorizationModel.isValid()) {
            AuthorizationCode authorizationCode = authorizationModel.getAuthorizationCode();
            if (authorizationCode != null) {
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .queryParam("code", authorizationCode.getAuthorizationCode())
                        .queryParam("state", authorizationCode.getState())
                        .queryParam("scope", authorizationCode.getScope()).build();
                return "redirect:" + uri;
            } else if (authorizationModel.getAccessToken() != null) {
                String tokenFragment = oAuth2Service.createTokenResponseFragment(authorizationModel.getAccessToken(),
                        authorizationModel.getState());
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .fragment(tokenFragment).build();
                return "redirect:" + uri;
            } else {
                authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                authorizationModel.setErrorDescription("response_type is invalid");
                return buildErrorUrl(authorizationModel);
            }
        } else {
            return buildErrorUrl(authorizationModel);
        }
    }

    private String buildErrorUrl(AuthorizationModel authorizationModel) {
        if (authorizationModel.getRedirectUri() == null) {
            throw new OAuthException(authorizationModel.getErrorCode(), authorizationModel.getErrorDescription());
        }
        UriComponents redirect = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                .queryParam("error", authorizationModel.getErrorCode())
                .queryParam("error_description", authorizationModel.getErrorDescription()).build();
        return "redirect:" + redirect;
    }

    @SuppressWarnings("unchecked")
    private <T> T extractPrincipal(Authentication authentication, Class<T> userClass) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal != null && userClass.isInstance(principal)) {
                return (T) principal;
            }
        }
        return null;
    }
}
