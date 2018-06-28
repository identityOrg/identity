package net.prasenjit.identity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.oauth.GrantType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.persistence.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@Entity
@Table(name = "T_CLIENT")
public class Client implements UserDetails {
    private static final long serialVersionUID = 4183078040533025925L;

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
    private Set<Scope> scopes;

    @Column(name = "REDIRECT_URI", length = 500, nullable = false)
    private String redirectUri;

    @Column(name = "ACCESS_TOKEN_VALIDITY", nullable = false)
    private Duration accessTokenValidity;

    @Column(name = "REFRESH_TOKEN_VALIDITY", nullable = false)
    private Duration refreshTokenValidity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (CollectionUtils.isEmpty(scopes)) {
            return AuthorityUtils.createAuthorityList("CLIENT");
        } else {
            List<String> scopeList = scopes.stream()
                    .map(s -> s.getScopeId().toUpperCase())
                    .map(s -> "SCOPE_" + s).collect(Collectors.toList());
            scopeList.add("CLIENT");
            return AuthorityUtils.createAuthorityList(scopeList.toArray(new String[0]));
        }
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return clientSecret;
    }

    @Override
    public String getUsername() {
        return clientId;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        LocalDateTime now = LocalDateTime.now();
        if (expiryDate != null) {
            return now.isAfter(creationDate) && now.isBefore(expiryDate);
        } else {
            return now.isAfter(creationDate);
        }
    }


    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return status != Status.LOCKED;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return status == Status.ACTIVE;
    }

    public boolean supportsGrant(GrantType grant) {
        switch (grant) {
            case IMPLICIT:
                return !isSecureClient();
            case PASSWORD:
            case REFRESH_TOKEN:
            case CLIENT_CREDENTIALS:
                return isSecureClient();
            case AUTHORIZATION_CODE:
                return true;
            default:
                return false;
        }
    }

    @JsonIgnore
    public boolean isSecureClient() {
        return StringUtils.hasText(clientSecret);
    }

    public String getApprovedScopes() {
        if (!CollectionUtils.isEmpty(this.scopes)) {
            return this.scopes.stream().map(Scope::getScopeId).reduce((x, y) -> x + " " + y).orElse(null);
        }
        return null;
    }

    public void setApprovedScopes(String approvedScopes) {
        if (StringUtils.hasText(approvedScopes)) {
            String[] scopes = StringUtils.delimitedListToStringArray(approvedScopes, " ");
            this.scopes = Stream.of(scopes).map(s -> new Scope(s, null)).collect(Collectors.toSet());
        } else {
            this.scopes = null;
        }
    }
}
