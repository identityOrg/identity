package net.prasenjit.identity.controller;

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
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
    public void deleteClient(@PathVariable("clientId") String clientID, HttpServletRequest servletRequest,
                             HttpServletResponse servletResponse) throws IOException {
        HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
        try {
            ClientDeleteRequest request = ClientDeleteRequest.parse(httpRequest);
            ClientRegistrationResponse response = registrationService.deleteClient(clientID, request);
            ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
        } catch (ParseException e) {
            ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(e.getErrorObject());
            ServletUtils.applyHTTPResponse(response.toHTTPResponse(), servletResponse);
        }
    }
}
