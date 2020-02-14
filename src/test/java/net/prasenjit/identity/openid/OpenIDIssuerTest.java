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

package net.prasenjit.identity.openid;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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

        assertEquals(issuer, opMetadata.getIssuer());

        // Print the metadata
        System.out.println(opMetadata.toJSONObject());
    }
}
