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
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.client.Client;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.mail.internet.ContentType;
import java.io.IOException;
import java.net.URL;

@Component
@RequiredArgsConstructor
public class JWTResolver implements ResourceRetriever {

    @Qualifier("cachingRestTemplate")
    private final RestTemplate restTemplate;
    private final CryptographyService cryptographyService;

    public AuthenticationRequest resolveAuthenticationRequest(AuthenticationRequest request, Client client)
            throws ParseException, ResolveException {
        if (request.specifiesRequestObject()) {
            OIDCClientMetadata metadata = client.getMetadata();
            if (metadata.getRequestObjectJWSAlg() == null &&
                    (metadata.getRequestObjectJWEAlg() == null ||
                            metadata.getRequestObjectJWEEnc() == null)) {
                throw new ResolveException(OIDCError.REQUEST_NOT_SUPPORTED, request);
            }
            JWTProcessor<SecurityContext> jwtProcessor = createJWTProcessor(metadata, request);
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

    private JWTProcessor<SecurityContext> createJWTProcessor(OIDCClientMetadata metadata,
                                                             AuthenticationRequest request)
            throws ParseException, ResolveException {
        JWEDecryptionKeySelector<SecurityContext> encKeySelector = null;
        JWSVerificationKeySelector<SecurityContext> signKeySelector = null;
        if (metadata.getRequestObjectJWSAlg() != null) {
            JWSAlgorithm algo = metadata.getRequestObjectJWSAlg();
            JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(getClientJWKSet(metadata, request));
            signKeySelector = new JWSVerificationKeySelector<>(algo, keySource);
        }
        if (metadata.getRequestObjectJWEAlg() != null
                && metadata.getRequestObjectJWEEnc() != null) {
            JWEAlgorithm jweAlg = metadata.getRequestObjectJWEAlg();
            EncryptionMethod jweEnc = metadata.getRequestObjectJWEEnc();
            JWKSource<SecurityContext> opKeySource = new ImmutableJWKSet<>(cryptographyService.loadJwkKeys());
            encKeySelector = new JWEDecryptionKeySelector<>(jweAlg, jweEnc, opKeySource);
        }
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(signKeySelector);
        processor.setJWEKeySelector(encKeySelector);
        return processor;
    }

    private JWKSet getClientJWKSet(OIDCClientMetadata metadata, AuthenticationRequest request) throws ParseException, ResolveException {
        try {
            if (metadata.getJWKSet() != null) {
                return metadata.getJWKSet();
            } else if (metadata.getJWKSetURI() != null) {
                Resource jwksResource = retrieveResource(metadata.getJWKSetURI().toURL());
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
