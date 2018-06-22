package net.prasenjit.identity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Entity
@Table(name = "T_USER")
public class User implements UserDetails {
    private static final long serialVersionUID = -2840908062923870421L;

    @Id
    @Column(name = "USERNAME", length = 50, nullable = false, unique = true)
    private String username;

    @JsonIgnore
    @Column(name = "PASSWORD", length = 200, nullable = false)
    private String password;

    @Column(name = "STATUS", nullable = false)
    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE")
    private LocalDateTime expiryDate;

    @Column(name = "PASSWORD_EXPIRY_DATE", nullable = false)
    private LocalDateTime passwordExpiryDate;

    @Column(name = "ADMIN", nullable = false)
    private Boolean admin;

    @Column(name = "FIRST_NAME")
    private String firstName;

    @Column(name = "LAST_NAME")
    private String lastName;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return admin ? AuthorityUtils.createAuthorityList("USER", "ADMIN") : AuthorityUtils.createAuthorityList("USER");
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
        if (passwordExpiryDate != null) {
            return passwordExpiryDate.isAfter(LocalDateTime.now());
        }
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return status == Status.ACTIVE;
    }

    @JsonIgnore
    public boolean isValid() {
        return isAccountNonExpired() && isAccountNonLocked() && isEnabled();
    }
}
