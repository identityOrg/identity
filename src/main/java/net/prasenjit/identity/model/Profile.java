package net.prasenjit.identity.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class Profile implements UserDetails {

    private LocalDateTime expiryDate;
    private LocalDateTime passwordExpiryDate;
    private List<SimpleGrantedAuthority> authorities;
    private LocalDateTime creationDate;
    private String username;
    private String firstName;
    private String lastName;
    private Status status;
    private boolean client;

    @JsonCreator
    public Profile() {
    }

    private Profile(User user) {
        this.username = user.getUsername();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.creationDate = user.getCreationDate();
        this.expiryDate = user.getExpiryDate();
        this.passwordExpiryDate = user.getPasswordExpiryDate();
        this.authorities = new ArrayList<>();
        user.getAuthorities().stream()
                .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
                .forEach(a -> this.authorities.add(a));
        this.status = user.getStatus();
        this.client = false;
    }

    private Profile(Client client) {
        this.username = client.getUsername();
        this.firstName = client.getClientName();
        this.creationDate = client.getCreationDate();
        this.expiryDate = client.getExpiryDate();
        this.authorities = new ArrayList<>();
        client.getAuthorities().stream()
                .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
                .forEach(a -> this.authorities.add(a));
        this.status = client.getStatus();
        this.client = true;
    }

    public static Profile create(UserDetails userDetails) {
        if (userDetails instanceof User) {
            return new Profile((User) userDetails);
        } else {
            return new Profile((Client) userDetails);
        }
    }

    @Override
    public String getPassword() {
        return null;
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
        return passwordExpiryDate == null || passwordExpiryDate.isAfter(LocalDateTime.now());
    }

    @Override
    public boolean isEnabled() {
        return status == Status.ACTIVE;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    private static class SimpleGrantedAuthority implements GrantedAuthority {
        private String authority;
    }
}
