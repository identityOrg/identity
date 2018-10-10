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

package net.prasenjit.identity.controller;

import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.op.ResolveException;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.IdentityViewResponse;
import net.prasenjit.identity.service.OAuth2Service;
import net.prasenjit.identity.service.OpenIDConnectService;
import net.prasenjit.identity.service.UserInfoService;

@Controller
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

	private final OpenIDConnectService openIDConnectService;
	private final OAuth2Service oAuth2Service;
	private final UserInfoService userInfoService;

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
	public void introspection(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
			throws IOException {
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
			return ResponseEntity.status(e.getErrorObject().getHTTPStatusCode()).contentType(MediaType.APPLICATION_JSON)
					.body(e.getErrorObject().toJSONObject());
		}
	}

	@RequestMapping(value = "userinfo", method = { RequestMethod.GET,
			RequestMethod.POST }, produces = MediaType.APPLICATION_JSON_VALUE)
	public void userInfo(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		try {
			UserInfoRequest request = UserInfoRequest.parse(httpRequest);
			UserInfoResponse response = userInfoService.retrieveUserInfo(request);
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		} catch (ParseException e) {
			servletResponse.setStatus(e.getErrorObject().getHTTPStatusCode());
			servletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
			servletResponse.getWriter().println(e.getErrorObject().toJSONObject().toJSONString());
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
