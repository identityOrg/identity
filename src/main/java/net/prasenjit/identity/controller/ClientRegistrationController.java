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

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.service.openid.DynamicRegistrationService;

@RestController
@RequestMapping("api/client-registration")
@RequiredArgsConstructor
public class ClientRegistrationController {

	private final DynamicRegistrationService registrationService;

	@PostMapping
	public void registerClient(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
			throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		try {
			OIDCClientRegistrationRequest request = OIDCClientRegistrationRequest.parse(httpRequest);
			ClientRegistrationResponse response = registrationService.registerClient(request);
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		} catch (ParseException e) {
			ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		}
	}

	@PutMapping("{clientId}")
	public void updateClient(@PathVariable("clientId") String clientID, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		try {
			OIDCClientUpdateRequest request = OIDCClientUpdateRequest.parse(httpRequest);
			ClientRegistrationResponse response = registrationService.updateClient(clientID, request);
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		} catch (ParseException e) {
			ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		}
	}

	@GetMapping("{clientId}")
	public void readClient(@PathVariable("clientId") String clientID, HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		try {
			ClientReadRequest request = ClientReadRequest.parse(httpRequest);
			ClientRegistrationResponse response = registrationService.readClient(clientID, request);
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		} catch (ParseException e) {
			ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(e.getErrorObject());
			ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
		}
	}

	@DeleteMapping("{clientId}")
	public ResponseEntity<Void> deleteClient(@PathVariable("clientId") String clientID,
			HttpServletRequest servletRequest) throws IOException {
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		try {
			ClientDeleteRequest request = ClientDeleteRequest.parse(httpRequest);
			int response = registrationService.deleteClient(clientID, request);
			return ResponseEntity.status(response).build();
		} catch (ParseException e) {
			return ResponseEntity.status(e.getErrorObject().getHTTPStatusCode()).build();
		}
	}
}
