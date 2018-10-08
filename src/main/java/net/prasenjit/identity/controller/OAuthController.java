package net.prasenjit.identity.controller;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.op.ResolveException;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.service.OAuth2Service;
import net.prasenjit.identity.service.OpenIDConnectService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.util.Map;

import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Controller
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OpenIDConnectService openIDConnectService;
    private final OAuth2Service oAuth2Service;

    @RequestMapping(value = "token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public void handleToken(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        try {
            HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
            TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

            TokenResponse tokenResponse = oAuth2Service.handleTokenRequest(tokenRequest);
            ServletUtils.applyHTTPResponse(tokenResponse.toHTTPResponse(), servletResponse);
        } catch (ParseException e) {
            TokenResponse tokenResponse = new TokenErrorResponse(e.getErrorObject());
            ServletUtils.applyHTTPResponse(tokenResponse.toHTTPResponse(), servletResponse);
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

    @PostMapping(value = "introspection")
    public void introspection(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        TokenIntrospectionResponse response;
        try {
            TokenIntrospectionRequest request = TokenIntrospectionRequest.parse(httpRequest);
            response = oAuth2Service.introspectToken(request);
        } catch (ParseException e) {
            response = new TokenIntrospectionErrorResponse(e.getErrorObject());
        }
        HTTPResponse httpResponse = response.toHTTPResponse();
        ServletUtils.applyHTTPResponse(httpResponse, servletResponse);
    }

    @PostMapping(value = "revocation")
    public ResponseEntity<?> revocation(HttpServletRequest servletRequest) throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        try {
            TokenIntrospectionRequest request = TokenIntrospectionRequest.parse(httpRequest);
            boolean revoked = oAuth2Service.revokeToken(request);
            if (revoked) {
                return ResponseEntity.status(200).build();
            } else {
                return ResponseEntity.status(401).build();
            }
        } catch (ParseException e) {
            return ResponseEntity.status(e.getErrorObject().getHTTPStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(e.getErrorObject().toJSONObject());
        }
    }

    private AuthorizationResponse generateParseError(GeneralException e) {
        AuthorizationResponse response;
        if (e.getRedirectionURI() != null) {
            response = new AuthorizationErrorResponse(e.getRedirectionURI(), e.getErrorObject(), e.getState(),
                    e.getResponseMode());
        } else if (e.getClientID() != null) {
            URI redirectUri = oAuth2Service.getRedirectUriForClientId(e.getClientID());
            if (redirectUri != null) {
                response = new AuthorizationErrorResponse(redirectUri, e.getErrorObject(), e.getState(),
                        e.getResponseMode());
            } else {
                response = new IdentityViewResponse(e.getErrorObject());
            }
        } else {
            response = new IdentityViewResponse(e.getErrorObject());
        }
        return response;
    }

    private String generateResponse(HttpSession httpSession, Model model, AuthorizationResponse response,
                                    URI authReqUri, ConsentModel consentModel) {
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
