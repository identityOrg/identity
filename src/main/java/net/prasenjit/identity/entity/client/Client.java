package net.prasenjit.identity.entity.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.ScopeEntity;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.converter.AbstractJsonConverter;
import net.prasenjit.identity.model.openid.registration.ApplicationType;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.ResponseType;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.util.CollectionUtils;

import javax.persistence.*;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@Entity
@Table(name = "T_CLIENT")
public class Client {

    @Id
    @Column(name = "CLIENT_ID", length = 50, nullable = false, unique = true)
    private String clientId;

    @Column(name = "CLIENT_NAME", length = 500, nullable = false)
    private String clientName;

    @JsonIgnore
    @Column(name = "CLIENT_SECRET", length = 50)
    private String clientSecret;

    @Column(name = "STATUS", nullable = false)
    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE")
    private LocalDateTime expiryDate;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "T_CLIENT_SCOPE",
            joinColumns = @JoinColumn(name = "CLIENT_ID", referencedColumnName = "CLIENT_ID"),
            inverseJoinColumns = @JoinColumn(name = "SCOPE_ID", referencedColumnName = "SCOPE_ID"))
    private Set<ScopeEntity> scopes;

    @Column(name = "REDIRECT_URI", length = 500, nullable = false)
    @Convert(converter = AbstractJsonConverter.StringArrayConverter.class)
    private String[] redirectUris;

    @Column(name = "ACCESS_TOKEN_VALIDITY", nullable = false)
    private Duration accessTokenValidity;

    @Column(name = "REFRESH_TOKEN_VALIDITY", nullable = false)
    private Duration refreshTokenValidity;

    @Column(name = "APPROVED_GRANTS", nullable = false)
    @Convert(converter = AbstractJsonConverter.GrantTypeArrayConverter.class)
    private GrantType[] approvedGrants;

    @Column(name = "APPROVED_RESPONSE_TYPE", nullable = false)
    @Convert(converter = AbstractJsonConverter.ResponseTypeArrayConverter.class)
    private ResponseType[] approvedResponseTypes;

    @Column(name = "APPLICATION_TYPE", length = 50, nullable = false)
    @Enumerated(EnumType.STRING)
    private ApplicationType applicationType;

    @Column(name = "CONTACTS")
    @Convert(converter = AbstractJsonConverter.StringArrayConverter.class)
    private String[] contacts;

    @Column(name = "URI_CONTAINER")
    @Convert(converter = AbstractJsonConverter.URIInfoConverter.class)
    private URIInfoContainer uriContainer;

    @Column(name = "JWKS_URI")
    private URL jwksUri;

    @Lob
    @Column(name = "JWKS")
    private String jwks;

    @Column(name = "SECURITY_CONTAINER")
    @Convert(converter = AbstractJsonConverter.SecurityInfoConverter.class)
    private SecurityInfoContainer securityContainer;

    public boolean supportsGrant(GrantType grant) {
        return approvedGrants != null && ArrayUtils.contains(approvedGrants, grant);
    }

    public String getApprovedScopes() {
        if (!CollectionUtils.isEmpty(this.scopes)) {
            return this.scopes.stream().map(ScopeEntity::getScopeId).reduce((x, y) -> x + " " + y).orElse(null);
        }
        return null;
    }
}
