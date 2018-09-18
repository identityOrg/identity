package net.prasenjit.identity.oauth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import net.prasenjit.identity.HtmlPageTestBase;

public class ClientCredentialTestTests extends HtmlPageTestBase {

	@Test
	public void clientCredentialGrant() throws ParseException, IOException {
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		ClientCredentialsGrant grant = new ClientCredentialsGrant();
		Scope scope = Scope.parse("scope1");
		TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		assertTrue(tokenResponse.indicatesSuccess());

		assertNotNull(tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken());
	}

}
