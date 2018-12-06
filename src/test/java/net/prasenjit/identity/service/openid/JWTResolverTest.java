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

package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.op.ResolveException;
import net.prasenjit.identity.HtmlPageTestBase;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.repository.ClientRepository;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

import static org.junit.Assert.assertTrue;

public class JWTResolverTest extends HtmlPageTestBase {

    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private JWTResolver requestJWTResolver;
    @Autowired
    private CryptographyService cryptographyService;

    @Test
    @Transactional
    public void testJWTResolve() throws ParseException, java.text.ParseException, JOSEException, ResolveException {
        Client client = clientRepository.getOne(clientInformation.getID().getValue());

        JWK key = null;
        JWK encKey = null;
        RSASSASigner signer = null;
        RSAEncrypter encrypter = null;
        for (JWK jwk : jwkSet.getKeys()) {
            if (jwk.getKeyUse() == KeyUse.SIGNATURE) {
                key = jwk;
                signer = new RSASSASigner((RSAKey) jwk);
            }
        }
        for (JWK jwk : cryptographyService.loadJwkKeys().getKeys()) {
            if (jwk.getKeyUse() == KeyUse.ENCRYPTION) {
                encKey = jwk;
                encrypter = new RSAEncrypter((RSAKey) jwk);
            }
        }

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("")
                .issuer(clientInformation.getID().getValue())
                .issueTime(new Date())
                .claim("scope", "openid email")
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        signedJWT.sign(signer);

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .contentType("JWT")
                        .keyID(encKey.getKeyID())
                        .build(),
                new Payload(signedJWT));
        jweObject.encrypt(encrypter);

        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                Scope.parse("openid"),
                clientInformation.getID(), getRedirectURI())
                .requestObject(JWTParser.parse(jweObject.serialize()))
                .build();

        AuthenticationRequest resolved = requestJWTResolver.resolveAuthenticationRequest(request, client);
        assertTrue(resolved.getScope().contains(OIDCScopeValue.EMAIL));
    }
}