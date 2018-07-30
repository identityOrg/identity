package net.prasenjit.identity.service.openid;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.Scope;
import net.prasenjit.identity.model.openid.discovery.DiscoveryResponse;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.properties.ServerMetadata;
import net.prasenjit.identity.repository.ScopeRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MetadataService {

    private static final String IDENTITY_PROVIDER_REL = "http://openid.net/specs/connect/1.0/issuer";

    private final IdentityProperties identityProperties;
    private final ScopeRepository scopeRepository;
    private boolean initialized = false;
    //@Value("local.server.port")
    private int serverPort;

    public ServerMetadata findMetadata() {
        UriComponentsBuilder builder = ServletUriComponentsBuilder.fromHttpUrl("http://localhost:8080");
        ServerMetadata metadata = identityProperties.getServerMetadata();
        if (!initialized) {
            if (!StringUtils.hasText(metadata.getIssuer())) {
                UriComponentsBuilder builder1 = builder.cloneBuilder();
                metadata.setIssuer(builder1.build().toString());
                metadata.setAuthorizationEndpoint(builder1.pathSegment("oauth", "authorize").build().toString());
                builder1 = builder.cloneBuilder();
                metadata.setTokenEndpoint(builder1.pathSegment("oauth", "token").toUriString());
                builder1 = builder.cloneBuilder();
                metadata.setUserinfoEndpoint(builder1.pathSegment("api", "me").toUriString());
                builder1 = builder.cloneBuilder();
                metadata.setJwksURI(builder1.pathSegment("api", "keys").toUriString());
            }
            metadata.setScopesSupported(scopeRepository.findAll().stream().map(Scope::getScopeId).collect(Collectors.toList()));
            metadata.setResponseTypesSupported(new String[]{"code", "code id_token", "id_token", "token id_token"});
            metadata.setGrantTypesSupported(new String[]{"authorization_code", "implicit"});
            metadata.setSubjectTypesSupported(new String[]{"public", "pairwise"});
            metadata.setIdTokenSigningAlgValuesSupported(new String[]{"RS256", "ES256", "HS256"});
            metadata.setIdTokenEncryptionAlgValuesSupported(new String[]{"RSA1_5", "A128KW"});
            metadata.setIdTokenEncryptionEncValuesSupported(new String[]{"A128CBC-HS256", "A128GCM"});
            metadata.setUserinfoSigningAlgValuesSupported(new String[]{"RS256", "ES256", "HS256"});
            metadata.setUserinfoEncryptionAlgValuesSupported(new String[]{"RSA1_5", "A128KW"});
            metadata.setUserinfoEncryptionEncValuesSupported(new String[]{"A128CBC-HS256", "A128GCM"});
            metadata.setRequestObjectSigningAlgValuesSupported(new String[]{"none", "RS256", "ES256"});
            metadata.setTokenEndpointAuthMethodsSupported(new String[]{"client_secret_basic"});
            metadata.setTokenEndpointAuthSigningAlgValuesSupported(new String[]{"RS256", "ES256"});
            metadata.setClaimsSupported(new String[]{"sub", "iss", "auth_time", "acr", "name",
                    "given_name", "family_name", "nickname", "profile", "picture", "website",
                    "email", "email_verified", "locale", "zoneinfo", "http://example.info/claims/groups"});
            metadata.setRequireRequestURIRegistration(true);
            initialized = true;
        }
        return metadata;
    }

    public DiscoveryResponse findWebFinder(String rel, String resource) {
        DiscoveryResponse discoveryResponse = new DiscoveryResponse();
        discoveryResponse.setSubject(resource);
        discoveryResponse.getLinks().add(new DiscoveryResponse.Link(IDENTITY_PROVIDER_REL,
                findMetadata().getIssuer()));
        return discoveryResponse;

    }
}
