package net.prasenjit.identity.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Entity
public class User implements UserDetails {
    @Id
    private String username;

    private String password;

    private Status status;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;

    private LocalDateTime passwordExpiryDate;

    private boolean admin;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return admin ? AuthorityUtils.createAuthorityList("USER", "ADMIN") : AuthorityUtils.createAuthorityList("USER");
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
        if (passwordExpiryDate != null) {
            return passwordExpiryDate.isAfter(LocalDateTime.now());
        }
        return true;
    }

    @Override
    public boolean isEnabled() {
        return status == Status.ACTIVE;
    }
}
