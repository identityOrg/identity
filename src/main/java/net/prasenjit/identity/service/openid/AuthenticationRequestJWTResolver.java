package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.Resource;
import com.nimbusds.oauth2.sdk.http.ResourceRetriever;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.op.AuthenticationRequestResolver;
import com.nimbusds.openid.connect.sdk.op.ResolveException;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.client.SecurityInfoContainer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.mail.internet.ContentType;
import java.io.IOException;
import java.net.URL;

@Component
@RequiredArgsConstructor
public class AuthenticationRequestJWTResolver implements ResourceRetriever {

    @Qualifier("cachingRestTemplate")
    private final RestTemplate restTemplate;
    private final CryptographyService cryptographyService;

    public AuthenticationRequest resolve(AuthenticationRequest request, Client client)
            throws ParseException, ResolveException {
        if (request.specifiesRequestObject()) {
            SecurityInfoContainer securityContainer = client.getSecurityContainer();
            if (securityContainer.getRequestObjectSigningAlgo() == null &&
                    (securityContainer.getRequestObjectEncryptionAlgo() == null ||
                            securityContainer.getRequestObjectEncryptionEnc() == null)) {
                throw new ResolveException(OIDCError.REQUEST_NOT_SUPPORTED, request);
            }
            JWTProcessor<SecurityContext> jwtProcessor = createJWTProcessor(client, securityContainer, request);
            AuthenticationRequestResolver<SecurityContext> requestResolver =
                    new AuthenticationRequestResolver<>(jwtProcessor, this);

            try {
                return requestResolver.resolve(request, null);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }
        return request;
    }

    private JWTProcessor<SecurityContext> createJWTProcessor(Client client,
                                                             SecurityInfoContainer securityContainer,
                                                             AuthenticationRequest request)
            throws ParseException, ResolveException {
        JWEDecryptionKeySelector<SecurityContext> encKeySelector = null;
        JWSVerificationKeySelector<SecurityContext> signKeySelector = null;
        if (securityContainer.getRequestObjectSigningAlgo() != null) {
            JWSAlgorithm algo = securityContainer.getRequestObjectSigningAlgo().getValue();
            JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(getClientJWKSet(client, request));
            signKeySelector = new JWSVerificationKeySelector<>(algo, keySource);
        }
        if (securityContainer.getRequestObjectEncryptionAlgo() != null
                && securityContainer.getRequestObjectEncryptionEnc() != null) {
            JWEAlgorithm jweAlg = securityContainer.getRequestObjectEncryptionAlgo().getValue();
            EncryptionMethod jweEnc = securityContainer.getRequestObjectEncryptionEnc().getValue();
            JWKSource<SecurityContext> opKeySource = new ImmutableJWKSet<>(cryptographyService.loadJwkKeys());
            encKeySelector = new JWEDecryptionKeySelector<>(jweAlg, jweEnc, opKeySource);
        }
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(signKeySelector);
        processor.setJWEKeySelector(encKeySelector);
        return processor;
    }

    private JWKSet getClientJWKSet(Client client, AuthenticationRequest request) throws ParseException, ResolveException {
        try {
            if (StringUtils.hasText(client.getJwks())) {
                return JWKSet.parse(client.getJwks());
            } else if (client.getJwksUri() != null) {
                Resource jwksResource = retrieveResource(client.getJwksUri());
                return JWKSet.parse(jwksResource.getContent());
            } else {
                throw new ResolveException(OIDCError.REQUEST_NOT_SUPPORTED
                        .appendDescription(":Registered client doesnot have key set"), request);
            }
        } catch (java.text.ParseException e) {
            throw new ParseException("Client keyset has error",
                    OIDCError.REQUEST_NOT_SUPPORTED.appendDescription(":Registered client key set is invalid"),
                    request.getClientID(), request.getRedirectionURI(), request.getResponseMode(),
                    request.getState());
        } catch (IOException e) {
            throw new ResolveException(OIDCError.REQUEST_NOT_SUPPORTED
                    .appendDescription(":Registered client key set retrieval failed"), request);
        }
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        ResponseEntity<String> forEntity = restTemplate.getForEntity(url.toString(), String.class);

        ContentType contentType;
        try {
            contentType = new ContentType(forEntity.getHeaders().getContentType().toString());
        } catch (Exception e) {
            throw new IOException("Couldn't parse Content-Type header: " + e.getMessage(), e);
        }
        return new Resource(forEntity.getBody(), contentType);
    }
}
