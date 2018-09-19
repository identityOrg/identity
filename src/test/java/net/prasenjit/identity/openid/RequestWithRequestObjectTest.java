package net.prasenjit.identity.openid;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import net.prasenjit.identity.HtmlPageTestBase;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.repository.ClientRepository;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RequestWithRequestObjectTest extends HtmlPageTestBase {

    @Autowired
    private ClientRepository clientRepository;

    @Test
    @Transactional(readOnly = true)
    public void teJwksObject() throws Exception {
        Client client = clientRepository.getOne(clientID.getValue());
        AuthenticationRequest.Builder requestBuilder = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                Scope.parse("openid"), clientID, getRedirectURI())
                .state(new State())
                .nonce(new Nonce())
                .endpointURI(getAuthorizeURI());

        requestBuilder.requestObject(createRequestObject(client, ResponseType.parse("token id_token")));

        AuthenticationRequest request = requestBuilder.build();

        clearContext(true, true);
        URI startUrl = request.toURI();
        HtmlPage htmlPage = loginForConsentPage(startUrl, "admin", "admin");
        URI uri = this.acceptAllConcent(htmlPage);

        AuthenticationResponse response = AuthenticationResponseParser.parse(uri);

        assertTrue(response.indicatesSuccess());
        assertNotNull(response.toSuccessResponse().getIDToken());
        assertTrue(response.toSuccessResponse().impliedResponseType().contains(OIDCResponseTypeValue.ID_TOKEN));
        assertTrue(response.toSuccessResponse().impliedResponseType().contains(ResponseType.Value.TOKEN));

        assertNotNull(htmlPage);
    }

    private JWT createRequestObject(Client client, ResponseType responseType) throws Exception {
        JWKSet keySet = client.getMetadata().getJWKSet();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().issuer(client.getClientId())
                .audience(getIssuerURI().toString())
                .claim("response_type", responseType.toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        RSASSASigner signer = new RSASSASigner((RSAKey) keySet.getKeyByKeyId("sign"));

        signedJWT.sign(signer);

        return signedJWT;
    }
}
