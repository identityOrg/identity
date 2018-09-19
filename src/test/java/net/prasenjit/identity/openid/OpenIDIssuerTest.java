package net.prasenjit.identity.openid;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class OpenIDIssuerTest extends HtmlPageTestBase {

    @Test
    public void testOpenIDProviderConfigFetch() throws Exception {
        // The OpenID provider issuer URL
        Issuer issuer = new Issuer(getIssuerURI());

        // Will resolveAuthenticationRequest the OpenID provider metadata automatically
        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);

        // Make HTTP request
        HTTPRequest httpRequest = request.toHTTPRequest();
        HTTPResponse httpResponse = httpRequest.send();

        // Parse OpenID provider metadata
        OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());

        assertTrue(issuer.equals(opMetadata.getIssuer()));

        // Print the metadata
        System.out.println(opMetadata.toJSONObject());
    }
}
