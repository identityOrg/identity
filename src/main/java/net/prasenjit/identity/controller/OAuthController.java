package net.prasenjit.identity.controller;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.op.ResolveException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.service.OAuth2Service;
import net.prasenjit.identity.service.OpenIDConnectService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    private final OpenIDConnectService openIDConnectService;
    private final OAuth2Service oAuth2Service;

    @RequestMapping(value = "token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public ResponseEntity<JSONObject> handleToken(@RequestBody String body, @RequestHeader("Authorization") String authz) throws MalformedURLException {
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

            TokenResponse tokenResponse = oAuth2Service.handleTokenRequest(tokenRequest);
            JSONObject jsonObject;
            if (tokenResponse.indicatesSuccess()) {
                jsonObject = tokenResponse.toSuccessResponse().toJSONObject();
                return ResponseEntity.status(HttpStatus.OK).body(jsonObject);
            } else {
                jsonObject = tokenResponse.toErrorResponse().toJSONObject();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(jsonObject);
            }
        } catch (ParseException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getErrorObject().toJSONObject());
        }
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
                response = oAuth2Service.processAuthorization(consentModel, authorizationRequest);
            }
        } catch (ParseException | ResolveException e) {
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
                response = oAuth2Service.processAuthorization(consentModel, authorizationRequest);
            }
        } catch (ParseException | ResolveException e) {
            response = generateParseError(e);
        }
        return generateResponse(httpSession, model, response, authReqUri, consentModel);
    }

    private AuthorizationResponse generateParseError(GeneralException e) {
        AuthorizationResponse response;
        if (e.getRedirectionURI() != null) {
            response = new AuthorizationErrorResponse(e.getRedirectionURI(),
                    e.getErrorObject(), e.getState(), e.getResponseMode());
        } else if (e.getClientID() != null) {
            URI redirectUri = oAuth2Service.getRedirectUriForClientId(e.getClientID().getValue());
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
            model.addAllAttributes(identityViewResponse.getAttributes());
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
}
