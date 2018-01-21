package net.prasenjit.identity.entity;

import lombok.Data;
import net.prasenjit.identity.oauth.GrantType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Entity
@Table(name = "T_CLIENT")
public class Client implements UserDetails {
    @Id
    @Column(name = "CLIENT_ID", length = 50, nullable = false, unique = true)
    private String clientId;

    @Column(name = "CLIENT_NAME", length = 500, nullable = false)
    private String clientName;

    @Column(name = "CLIENT_SECRET", length = 50)
    private String clientSecret;

    @Column(name = "STATUS", nullable = false)
    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE")
    private LocalDateTime expiryDate;

    @Column(name = "APPROVED_SCOPE", length = 500, nullable = false)
    private String approvedScopes;

    @Column(name = "REDIRECT_URI", length = 500, nullable = false)
    private String redirectUri;

    @Column(name = "ACCESS_TOKEN_VALIDITY", nullable = false)
    private Duration accessTokenValidity;

    @Column(name = "REFRESH_TOKEN_VALIDITY", nullable = false)
    private Duration refreshTokenValidity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return AuthorityUtils.createAuthorityList("CLIENT");
    }

    @Override
    public String getPassword() {
        return clientSecret;
    }

    @Override
    public String getUsername() {
        return clientId;
    }

    @Override
    public boolean isAccountNonExpired() {
        LocalDateTime now = LocalDateTime.now();
        if (expiryDate != null) {
            return now.isAfter(creationDate) && now.isBefore(expiryDate);
        } else {
            return now.isAfter(creationDate);
        }
    }

    @Override
    public boolean isAccountNonLocked() {
        return status != Status.LOCKED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
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

    public boolean isSecureClient() {
        return null != clientSecret;
    }
}
