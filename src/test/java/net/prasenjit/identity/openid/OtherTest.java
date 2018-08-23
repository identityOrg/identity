package net.prasenjit.identity.openid;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;

public class OtherTest {

    // Get the query string
    URI query = URI.create("https://server.example.com/op/authorize?" +
            "response_type=code&" +
            "client_id=client&" +
            "scope=" + URLEncoder.encode("openid profile", "utf-8") + "&" +
            "redirect_uri=http://localhost:4200/callback&" +
            "state=1234&" +
            "response_mode=fragment");

    public OtherTest() throws UnsupportedEncodingException {
    }

    @Test
    public void serverSideSDKTest() throws ParseException {

        // Decode the query string
        AuthenticationRequest req = AuthenticationRequest.parse(query);


        System.out.println(req.getClientID());
        System.out.println(req.getRedirectionURI());
        System.out.println(req.getEndpointURI());

        ResponseMode responseMode = req.getResponseMode() == null ? ResponseMode.QUERY : req.getResponseMode();
        AuthorizationCode code = new AuthorizationCode("1234567890");
        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(req.getRedirectionURI(),
                code, null, null, req.getState(), null, responseMode);

        System.out.println(response.toURI());

    }

    @Test
    public void testOAuthServerSide() throws ParseException {
        AuthorizationRequest request = AuthorizationRequest.parse(query);

        System.out.println(request.getClientID());
        System.out.println(request.getScope());

        AccessToken token = new BearerAccessToken("12309", 100, null);

        AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
                request.getRedirectionURI(), new AuthorizationCode("123"), token, request.getState(),
                null);

        System.out.println(response.toURI());
        System.out.println(response.impliedResponseMode());
        System.out.println(response.impliedResponseType());
    }

    @Test
    public void testPasswordGrant() throws Exception {

        URI url = URI.create("http://localhost:8080/oauth/token");

        // Construct the password grant from the username and password
        String username = "admin";
        Secret password = new Secret("admin");
        AuthorizationGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant(username, password);

        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID("client");
        Secret clientSecret = new Secret("client");
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // The request scope for the token (may be optional)
        Scope scope = new Scope("read", "write");

        // Make the token request
        TokenRequest request = new TokenRequest(url, clientAuth, passwordGrant, scope);

        HTTPResponse response = request.toHTTPRequest().send();
        System.out.println(response.getStatusMessage());
    }
}
