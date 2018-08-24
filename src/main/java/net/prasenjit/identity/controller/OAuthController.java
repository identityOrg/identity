package net.prasenjit.identity.controller;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.exception.UnauthenticatedClientException;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.service.OAuth2Service;
import net.prasenjit.identity.service.OAuth2Service1;
import net.prasenjit.identity.service.OpenIDConnectService;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpSession;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Map;

import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Slf4j
@Controller
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;
    private final OpenIDConnectService openIDConnectService;
    private final OAuth2Service1 oAuth2Service1;

    @RequestMapping(value = "token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public JSONObject handleToken(@RequestBody String body, @RequestHeader("Authorization") String authz) throws MalformedURLException {
        URI authReqUri = ServletUriComponentsBuilder.fromCurrentRequest().build(true).toUri();
        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, authReqUri.toURL());
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        Map<String, String> stringMap = URLUtils.parseParameters(body);
        Map<String, String> parameters = httpRequest.getQueryParameters();
        parameters.putAll(stringMap);
        httpRequest.setQuery(URLUtils.serializeParameters(parameters));
        httpRequest.setAuthorization(authz);

        TokenRequest tokenRequest;
        try {
            tokenRequest = TokenRequest.parse(httpRequest);

            TokenResponse tokenResponse = oAuth2Service1.handleTokenRequest(tokenRequest);
            JSONObject jsonObject;
            if (tokenResponse.indicatesSuccess()) {
                jsonObject = tokenResponse.toSuccessResponse().toJSONObject();
            } else {
                jsonObject = tokenResponse.toErrorResponse().toJSONObject();
            }
            return jsonObject;
        } catch (ParseException e) {
            return e.getErrorObject().toJSONObject();
        }
    }

    @PostMapping(value = "token2", params = "grant_type=password")
    @ResponseBody
    public OAuthToken passwordGrantToken(@RequestParam(value = "username") String username,
                                         @RequestParam(value = "password") String password,
                                         @RequestParam(value = "scope", defaultValue = "") String scope,
                                         Authentication clientAuth) {
        log.info("Processing password grant");
        Profile client = extractPrincipal(clientAuth, Profile.class);
        if (client != null) {
            return oAuth2Service.processPasswordGrant(client, username, password, scope);
        } else {
            throw new UnauthenticatedClientException("unauthorized_client", "client not authenticated");
        }
    }

    @PostMapping(value = "token2", params = "grant_type=client_credentials")
    @ResponseBody
    public OAuthToken clientCredentialGrantToken(@RequestParam(value = "scope", defaultValue = "") String scope,
                                                 Authentication clientAuth) {
        log.info("Processing password grant");
        Profile client = extractPrincipal(clientAuth, Profile.class);
        if (client != null) {
            return oAuth2Service.processClientCredentialsGrant(client, scope);
        } else {
            throw new UnauthenticatedClientException("unauthorized_client", "client not authenticated");
        }
    }

    @PostMapping(value = "token2", params = "grant_type=authorization_code")
    @ResponseBody
    public OAuthToken authorizationCodeGrantToken(@RequestParam(value = "code", required = false) String code,
                                                  @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                                  @RequestParam(value = "client_id", required = false) String clientId,
                                                  Authentication authentication) {
        log.info("Processing password grant");
        Profile client = extractPrincipal(authentication, Profile.class);
        return oAuth2Service.processAuthorizationCodeGrantToken(client, code, redirectUri, clientId);
    }

    @PostMapping(value = "token2", params = "grant_type=refresh_token")
    @ResponseBody
    public OAuthToken refreshTokenGrantToken(
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            Authentication authentication) {
        log.info("Processing refresh token grant");
        Client client = extractPrincipal(authentication, Client.class);
        return oAuth2Service.processRefreshTokenGrantToken(client, refreshToken);
    }

    @RequestMapping(value = "authorized", method = RequestMethod.POST)
    public String submitConsent(@ModelAttribute ConsentModel consentModel, Model model, HttpSession httpSession) {
        AuthorizationResponse response;
        URI authReqUri = consentModel.getRequestUri();
        try {
            if (consentModel.isOpenid()) {
                AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(authReqUri);
                response = openIDConnectService.processAuthentication(consentModel, authenticationRequest);
            } else {
                AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(authReqUri);
                response = oAuth2Service1.processAuthorization(consentModel, authorizationRequest);
            }
        } catch (ParseException e) {
            response = generateParseError(e);
        }
        return generateResponse(httpSession, model, response, authReqUri, consentModel);
    }

    @RequestMapping(value = "authorize", method = RequestMethod.GET)
    public String authorizeGet(HttpSession httpSession, Model model, Authentication authentication) {
        AuthorizationResponse response;
        URI authReqUri = ServletUriComponentsBuilder.fromCurrentRequest().build(true).toUri();
        ConsentModel consentModel = new ConsentModel();
        consentModel.setRequestUri(authReqUri);
        try {
            AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(authReqUri);
            if (authorizationRequest.getScope() != null && authorizationRequest.getScope().contains("openid")) {
                consentModel.setOpenid(true);
                AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(authReqUri);
                response = openIDConnectService.processAuthentication(consentModel, authenticationRequest);
            } else {
                consentModel.setOpenid(false);
                if (authentication == null || !authentication.isAuthenticated()) {
                    httpSession.setAttribute(PREVIOUS_URL, authReqUri.toString());
                    return "redirect:/login";
                }
                response = oAuth2Service1.processAuthorization(consentModel, authorizationRequest);
            }
        } catch (ParseException e) {
            response = generateParseError(e);
        }
        return generateResponse(httpSession, model, response, authReqUri, consentModel);
    }

    private AuthorizationResponse generateParseError(ParseException e) {
        AuthorizationResponse response;
        if (e.getRedirectionURI() != null) {
            response = new AuthorizationErrorResponse(e.getRedirectionURI(),
                    e.getErrorObject(), e.getState(), e.getResponseMode());
        } else if (e.getClientID() != null) {
            URI redirectUri = oAuth2Service1.getRedirectUriForClientId(e.getClientID().getValue());
            if (redirectUri != null) {
                response = new AuthorizationErrorResponse(redirectUri,
                        e.getErrorObject(), e.getState(), e.getResponseMode());
            } else {
                response = new IdentityViewResponse(e.getErrorObject());
            }
        } else {
            response = new IdentityViewResponse(e.getErrorObject());
        }
        return response;
    }

    private String generateResponse(HttpSession httpSession, Model model, AuthorizationResponse response, URI authReqUri, ConsentModel consentModel) {
        if (response instanceof IdentityViewResponse) {
            IdentityViewResponse identityViewResponse = (IdentityViewResponse) response;
            IdentityViewResponse.ViewType viewType = identityViewResponse.getViewType();
            if (viewType == IdentityViewResponse.ViewType.LOGIN) {
                httpSession.setAttribute(PREVIOUS_URL, authReqUri.toString());
            } else if (viewType == IdentityViewResponse.ViewType.ERROR) {
                model.addAttribute("error", identityViewResponse.getErrorObject());
            } else {
                model.addAttribute("model", consentModel);
            }
            return viewType.getViewName();
        }
        if (response.impliedResponseMode() == ResponseMode.FORM_POST) {
            Map<String, String> responseMap;
            if (response.indicatesSuccess()) {
                responseMap = response.toSuccessResponse().toParameters();
            } else {
                responseMap = response.toErrorResponse().toParameters();
            }
            model.addAttribute("map", responseMap);
            return "post_response";
        } else {
            URI redirect;
            if (response.indicatesSuccess()) {
                redirect = response.toSuccessResponse().toURI();
            } else {
                redirect = response.toErrorResponse().toURI();
            }
            return "redirect:" + redirect.toString();
        }
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
