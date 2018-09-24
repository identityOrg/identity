package net.prasenjit.identity.clientregistry;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;

import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;

import net.prasenjit.identity.HtmlPageTestBase;

public class ClientRegistrationTest extends HtmlPageTestBase {

	@Test
	public void testRegistrationSuccess() throws ParseException, IOException {
		URI uri = oidcConfiguration.getRegistrationEndpointURI();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setName("Unit Test Client");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(),
				clientInformation.getSecret());
		ClientCredentialsGrant grant = new ClientCredentialsGrant();
		Scope scope = Scope.parse("scope1");
		TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		BearerAccessToken bearerAccessToken = tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
		OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(uri, metadata, bearerAccessToken);

		ClientRegistrationResponse response = OIDCClientRegistrationResponseParser
				.parse(request.toHTTPRequest().send());

		assertTrue(response.indicatesSuccess());

		ClientInformation info = response.toSuccessResponse().getClientInformation();
		OIDCClientMetadata clientMetadata = (OIDCClientMetadata) info.getMetadata();

		JWSAlgorithm alg = clientMetadata.getIDTokenJWSAlg();

		assertNotNull(alg);
		assertThat(JWSAlgorithm.RS256, is(alg));

		clientMetadata.setIDTokenJWSAlg(JWSAlgorithm.RS384);

		// check get information
		OIDCClientUpdateRequest updateRequest = new OIDCClientUpdateRequest(info.getRegistrationURI(), info.getID(),
				bearerAccessToken, clientMetadata, info.getSecret());

		response = OIDCClientRegistrationResponseParser.parse(updateRequest.toHTTPRequest().send());

		assertTrue(response.indicatesSuccess());

		info = response.toSuccessResponse().getClientInformation();
		clientMetadata = (OIDCClientMetadata) info.getMetadata();

		alg = clientMetadata.getIDTokenJWSAlg();

		assertNotNull(alg);
		assertThat(JWSAlgorithm.RS384, is(alg));

		ClientReadRequest readRequest = new ClientReadRequest(info.getRegistrationURI(), bearerAccessToken);

		response = OIDCClientRegistrationResponseParser.parse(readRequest.toHTTPRequest().send());

		assertTrue(response.indicatesSuccess());

		info = response.toSuccessResponse().getClientInformation();
		clientMetadata = (OIDCClientMetadata) info.getMetadata();

		alg = clientMetadata.getIDTokenJWSAlg();

		assertNotNull(alg);
		assertThat(JWSAlgorithm.RS384, is(alg));

		ClientDeleteRequest deleteRequest = new ClientDeleteRequest(info.getRegistrationURI(), bearerAccessToken);

		HTTPResponse httpResponse = deleteRequest.toHTTPRequest().send();

		assertThat(200, is(httpResponse.getStatusCode()));

		response = OIDCClientRegistrationResponseParser.parse(readRequest.toHTTPRequest().send());

		assertFalse(response.indicatesSuccess());
	}
}
