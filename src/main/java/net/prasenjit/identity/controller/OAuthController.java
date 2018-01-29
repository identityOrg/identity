package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.service.OAuth2Service;
import net.prasenjit.identity.service.OAuthError;
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
    public OAuthToken passwordGrantToken(
            @RequestParam(value = "username") String username,
            @RequestParam(value = "password") String password,
            @RequestParam(value = "scope", defaultValue = "") String scope,
            Authentication clientAuth) {
        if (clientAuth.isAuthenticated()) {
            log.info("Processing password grant");
            return oAuth2Service.processPasswordGrant((Client) clientAuth.getPrincipal(), username, password, scope);
        } else {
            throw new OAuthException("client not authenticated");
        }
    }

    @PostMapping(value = "token", params = "grant_type=client_credentials")
    @ResponseBody
    public OAuthToken clientCredentialGrantToken(
            @RequestParam(value = "scope", defaultValue = "") String scope,
            Authentication clientAuth) {
        if (clientAuth.isAuthenticated()) {
            log.info("Processing password grant");
            return oAuth2Service.processClientCredentialsGrant((Client) clientAuth.getPrincipal(), scope);
        } else {
            throw new OAuthException("client not authenticated");
        }
    }

    @PostMapping(value = "token", params = "grant_type=authorization_code")
    @ResponseBody
    public OAuthToken authorizationCodeGrantToken(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            Authentication authentication) {
        log.info("Processing password grant");
        Client client = null;
        if (authentication.isAuthenticated()) {
            client = (Client) authentication.getPrincipal();
        }
        return oAuth2Service.processAuthorizationCodeGrantToken(client, code, redirectUri, clientId);
    }

    @PostMapping(value = "token", params = "grant_type=refresh_token")
    @ResponseBody
    public OAuthToken refreshTokenGrantToken(
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            Authentication authentication) {
        log.info("Processing refresh token grant");
        Client client = null;
        if (authentication.isAuthenticated()) {
            client = (Client) authentication.getPrincipal();
        }
        return oAuth2Service.processRefreshTokenGrantToken(client, refreshToken);
    }

    @GetMapping("authorize")
    public String oAuthAuthorize(@RequestParam(value = "response_type", required = false) String responseType,
                                 @RequestParam(value = "client_id", required = false) String clientId,
                                 @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                 @RequestParam(value = "scope", defaultValue = "") String scope,
                                 @RequestParam(value = "state", required = false) String state,
                                 Authentication authentication, Model model) {
        AuthorizationModel authorizationModel = oAuth2Service.validateAuthorizationGrant(responseType,
                (User) authentication.getPrincipal(), clientId, scope, state, redirectUri);
        if (authorizationModel.isValid()) {
            model.addAttribute("model", authorizationModel);
            return "authorize";
        } else {
            return buildErrorUrl(authorizationModel);
        }
    }

    private String buildErrorUrl(AuthorizationModel authorizationModel) {
        if (authorizationModel.getRedirectUri() == null) {
            throw new OAuthException("redirect_uri not specified with error " + authorizationModel.getErrorCode()
                    + " description " + authorizationModel.getErrorDescription());
        }
        UriComponents redirect = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                .queryParam("error", authorizationModel.getErrorCode())
                .queryParam("error_description", authorizationModel.getErrorDescription())
                .build();
        return "redirect:" + redirect;
    }

    @PostMapping("authorize")
    public String submitAuthorize(@ModelAttribute AuthorizationModel authorizationModel, Authentication authentication) {
        authorizationModel.setUser((User) authentication.getPrincipal());
        authorizationModel = oAuth2Service.processAuthorizationOrImplicitGrant(authorizationModel);
        if (authorizationModel.isValid()) {
            AuthorizationCode authorizationCode = authorizationModel.getAuthorizationCode();
            if (authorizationCode != null) {
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .queryParam("code", authorizationCode.getAuthorizationCode())
                        .queryParam("state", authorizationCode.getState())
                        .queryParam("scope", authorizationCode.getScope())
                        .build();
                return "redirect:" + uri;
            } else if (authorizationModel.getAccessToken() != null) {
                String tokenFragment = oAuth2Service.createTokenResponseFragment(authorizationModel.getAccessToken(), authorizationModel.getState());
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .fragment(tokenFragment)
                        .build();
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
}
