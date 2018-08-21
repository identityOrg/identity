package net.prasenjit.identity.openid;

import com.nimbusds.oauth2.sdk.*;
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
}
