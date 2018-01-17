package net.prasenjit.identity.entity;

import lombok.Data;
import net.prasenjit.identity.oauth.GrantType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Entity
public class Client implements UserDetails {
    @Id
    private String clientId;

    private String clientName;

    private String clientSecret;

    private Status status;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;

    private String approvedScopes;

    private String redirectUri;

    private Duration accessTokenValidity;

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
