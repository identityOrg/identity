package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.ScopeEntity;
import net.prasenjit.identity.model.openid.discovery.DiscoveryResponse;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.properties.ServerMetadata;
import net.prasenjit.identity.repository.ScopeRepository;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@Service
@RequiredArgsConstructor
public class MetadataService {

    private static final String IDENTITY_PROVIDER_REL = "http://openid.net/specs/connect/1.0/issuer";

    private final IdentityProperties identityProperties;
    private final ScopeRepository scopeRepository;
    private boolean initialized = false;
    private int serverPort = 0;
    private AtomicReference<OIDCProviderMetadata> oidcMetadata = new AtomicReference<>();

    public DiscoveryResponse findWebFinder(String rel, String resource) {
        DiscoveryResponse discoveryResponse = new DiscoveryResponse();
        discoveryResponse.setSubject(resource);
        discoveryResponse.getLinks().add(new DiscoveryResponse.Link(IDENTITY_PROVIDER_REL,
                findOIDCConfiguration().getIssuer().toString()));
        return discoveryResponse;

    }

    @EventListener(WebServerInitializedEvent.class)
    public void containerInitialized(WebServerInitializedEvent event) {
        serverPort = event.getWebServer().getPort();
        initialized = false;
    }

    public OIDCProviderMetadata findOIDCConfiguration() {
        return oidcMetadata.updateAndGet(this::updateMetadata);
    }

    private OIDCProviderMetadata updateMetadata(OIDCProviderMetadata metadata) {
        if (metadata == null || !initialized) {
            ServerMetadata serverMetadata = identityProperties.getServerMetadata();
            UriComponentsBuilder builder;
            if (!StringUtils.hasText(serverMetadata.getIssuer())) {
                builder = ServletUriComponentsBuilder.fromHttpUrl("http://localhost");
                builder.port(serverPort);
            } else {
                builder = ServletUriComponentsBuilder.fromHttpUrl(serverMetadata.getIssuer());
            }
            UriComponentsBuilder builder1 = builder.cloneBuilder();
            Issuer issuer = new Issuer(builder1.build().toUri());
            List<SubjectType> subjectTypes = Collections.singletonList(SubjectType.PUBLIC);
            builder1 = builder.cloneBuilder();
            URI jwkSetUri = builder1.pathSegment("api", "keys").build().toUri();
            metadata = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetUri);

            builder1 = builder.cloneBuilder();
            metadata.setAuthorizationEndpointURI(builder1.pathSegment("oauth", "authorize").build().toUri());

            builder1 = builder.cloneBuilder();
            metadata.setTokenEndpointURI(builder1.pathSegment("oauth", "token").build().toUri());
            List<ClientAuthenticationMethod> epAuthMethods = new ArrayList<>();
            epAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            epAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
            metadata.setTokenEndpointAuthMethods(epAuthMethods);

            builder1 = builder.cloneBuilder();
            metadata.setUserInfoEndpointURI(builder1.pathSegment("api", "me").build().toUri());

            builder1 = builder.cloneBuilder();
            metadata.setRegistrationEndpointURI(builder1.pathSegment("api", "client-registration").build().toUri());

            builder1 = builder.cloneBuilder();
            metadata.setIntrospectionEndpointURI(builder1.pathSegment("oauth", "introspection").build().toUri());
            metadata.setIntrospectionEndpointAuthMethods(epAuthMethods);

            builder1 = builder.cloneBuilder();
            metadata.setRevocationEndpointURI(builder1.pathSegment("oauth", "revocation").build().toUri());
            metadata.setRevocationEndpointAuthMethods(epAuthMethods);

            scopeRepository.findAll().stream()
                    .map(ScopeEntity::getScopeId)
                    .reduce((x, y) -> x + " " + y)
                    .map(Scope::parse)
                    .ifPresent(metadata::setScopes);

            metadata.setClaimTypes(Collections.singletonList(ClaimType.NORMAL));

            List<JWSAlgorithm> jwsAlgos = new ArrayList<>();
            jwsAlgos.add(JWSAlgorithm.RS256);
            jwsAlgos.add(JWSAlgorithm.RS384);
            jwsAlgos.add(JWSAlgorithm.RS512);
            jwsAlgos.add(JWSAlgorithm.ES256);
            jwsAlgos.add(JWSAlgorithm.ES384);
            jwsAlgos.add(JWSAlgorithm.ES512);
            metadata.setIDTokenJWSAlgs(jwsAlgos);
            metadata.setUserInfoJWSAlgs(jwsAlgos);
            metadata.setRequestObjectJWSAlgs(jwsAlgos);

            List<JWEAlgorithm> jweAlgos = new ArrayList<>();
            jweAlgos.add(JWEAlgorithm.RSA_OAEP_256);
            jweAlgos.add(JWEAlgorithm.RSA_OAEP);
            metadata.setIDTokenJWEAlgs(jweAlgos);
            metadata.setUserInfoJWEAlgs(jweAlgos);
            metadata.setRequestObjectJWEAlgs(jweAlgos);

            List<EncryptionMethod> jweEncs = new ArrayList<>();
            jweEncs.add(EncryptionMethod.A128GCM);
            jweEncs.add(EncryptionMethod.A128CBC_HS256);
            metadata.setIDTokenJWEEncs(jweEncs);
            metadata.setUserInfoJWEEncs(jweEncs);
            metadata.setRequestObjectJWEEncs(jweEncs);

            metadata.setSupportsBackChannelLogout(false);
            metadata.setSupportsBackChannelLogoutSession(false);
            metadata.setSupportsClaimsParams(false);
            metadata.setSupportsFrontChannelLogout(false);
            metadata.setSupportsFrontChannelLogoutSession(false);
            metadata.setSupportsRequestParam(true);
            metadata.setSupportsRequestURIParam(true);
            metadata.setSupportsTLSClientCertificateBoundAccessTokens(false);
            metadata.setRequiresRequestURIRegistration(false);

            List<GrantType> grantTypes = new ArrayList<>();
            grantTypes.add(GrantType.AUTHORIZATION_CODE);
            grantTypes.add(GrantType.IMPLICIT);
            grantTypes.add(GrantType.PASSWORD);
            grantTypes.add(GrantType.CLIENT_CREDENTIALS);
            grantTypes.add(GrantType.REFRESH_TOKEN);
            metadata.setGrantTypes(grantTypes);

            try {
                List<ResponseType> responseTypes = new ArrayList<>();
                responseTypes.add(ResponseType.parse("code"));
                responseTypes.add(ResponseType.parse("id_token"));
                responseTypes.add(ResponseType.parse("id_token token"));
                responseTypes.add(ResponseType.parse("code id_token"));
                responseTypes.add(ResponseType.parse("code token"));
                responseTypes.add(ResponseType.parse("code id_token token"));
                metadata.setResponseTypes(responseTypes);
            } catch (ParseException e) {
                throw new RuntimeException("Fatal:: failed to parse response type", e);
            }

            scopeRepository.findAll().stream()
                    .map(ScopeEntity::getScopeId)
                    .reduce((x, y) -> x + " " + y)
                    .map(Scope::parse)
                    .ifPresent(metadata::setScopes);

            List<CodeChallengeMethod> methods = new ArrayList<>();
            methods.add(CodeChallengeMethod.PLAIN);
            methods.add(CodeChallengeMethod.S256);
            metadata.setCodeChallengeMethods(methods);

            List<ResponseMode> responseModes = new ArrayList<>();
            responseModes.add(ResponseMode.FRAGMENT);
            responseModes.add(ResponseMode.QUERY);
            responseModes.add(ResponseMode.FORM_POST);
            metadata.setResponseModes(responseModes);

            initialized = true;
        }
        return metadata;
    }

    public URI findClientRegistrationURI(String clientId) {
        Base64URL base64 = Base64URL.encode(clientId);
        return ServletUriComponentsBuilder.fromHttpUrl(findOIDCConfiguration().getIssuer().getValue())
                .pathSegment("api", "client-registration")
                .pathSegment(base64.toString()).build().toUri();
    }

    public Issuer getIssuer() {
        return findOIDCConfiguration().getIssuer();
    }
}
