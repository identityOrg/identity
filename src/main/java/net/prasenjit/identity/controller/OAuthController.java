package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.exception.UnauthenticatedClientException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.model.openid.OpenIDSessionContainer;
import net.prasenjit.identity.model.openid.core.AuthorizeRequest;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.OAuth2Service;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Slf4j
@Controller
@RequestMapping("oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;
    private final OpenIDSessionContainer sessionContainer;

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
    public String oAuthAuthorize(AuthorizeRequest request, Authentication authentication, Model model,
                                 AuthorizationModel authorizationModel, HttpServletRequest httpRequest)
            throws IOException, ServletException {
        log.info("Processing authorization code grant");
        authorizationModel = oAuth2Service.validateAuthorizationGrant(authentication, request, authorizationModel);
        if (authorizationModel.isValid()) {
            if (authorizationModel.isLoginRequired() && !sessionContainer.isInteractiveLoginDone()) {
                UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest();
                httpRequest.getSession().setAttribute(PREVIOUS_URL, builder.build().toString());
                return "redirect:/login";
            }
            model.addAttribute("model", authorizationModel);
            return "authorize";
        } else {
            return buildErrorUrl(authorizationModel);
        }
    }

    @PostMapping("authorize")
    public String submitAuthorize(@ModelAttribute AuthorizationModel authorizationModel,
                                  Authentication authentication) {
        Profile profile = extractPrincipal(authentication, Profile.class);
        authorizationModel.setProfile(profile);
        authorizationModel.setLoginTime(((UserAuthenticationToken) authentication).getLoginTime());
        authorizationModel = oAuth2Service.processAuthorizationOrImplicitGrant(authorizationModel);
        if (authorizationModel.isValid()) {
            boolean responseAsFragment = false;
            Map<String, String> responseMap = new HashMap<>();
            responseMap.put("scope", authorizationModel.getState());
            if (authorizationModel.requireTokenResponse()) {
                responseAsFragment = true;
                AccessToken token = authorizationModel.getAccessToken();
                responseMap.put("access_token", token.getAssessToken());
                responseMap.put("token_type", "bearer");
                long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), token.getExpiryDate());
                responseMap.put("expires_in", "" + expIn);
            }
            if (authorizationModel.requireIDTokenResponse()) {
                responseAsFragment = true;
                responseMap.put("id_token", authorizationModel.getIdToken());
            }
            if (authorizationModel.requireCodeResponse()) {
                responseMap.put("code", authorizationModel.getAuthorizationCode().getAuthorizationCode());
            }
            if (responseAsFragment) {
                String tokenFragment = oAuth2Service.createTokenResponseFragment(responseMap);
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .fragment(tokenFragment).build();
                return "redirect:" + uri;
            } else {
                String queryFragment = oAuth2Service.createTokenResponseFragment(responseMap);
                UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationModel.getRedirectUri())
                        .query(queryFragment).build();
                return "redirect:" + uri;
            }
        }
        authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
        authorizationModel.setErrorDescription("response_type is invalid");
        return buildErrorUrl(authorizationModel);
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
