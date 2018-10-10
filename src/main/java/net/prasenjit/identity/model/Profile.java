/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.entity.client.Client;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class Profile implements UserDetails {
	private static final long serialVersionUID = -8616676872755665605L;
	private LocalDateTime expiryDate;
    private LocalDateTime passwordExpiryDate;
    private List<SimpleGrantedAuthority> authorities;
    private LocalDateTime creationDate;
    private String username;
    private String firstName;
    @JsonIgnore
    private String password;
    private String lastName;
    private Status status;
    private Boolean locked;
    private Boolean active;
    private boolean client;

    @JsonCreator
    public Profile() {
    }

    private Profile(User user) {
        this.username = user.getUsername();
        UserInfo userInfo = user.getUserInfo();
		this.firstName = userInfo.getGivenName();
        this.lastName = userInfo.getFamilyName();
        this.creationDate = user.getCreationDate();
        this.expiryDate = user.getExpiryDate();
        this.passwordExpiryDate = user.getPasswordExpiryDate();
        this.authorities = new ArrayList<>();
        user.getAuthorities().stream()
                .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
                .forEach(a -> this.authorities.add(a));
        this.active = user.getActive();
        this.locked = user.getLocked();
        this.client = false;
    }

    private Profile(Client client) {
        this.username = client.getClientId();
        this.firstName = client.getClientName();
        this.creationDate = client.getCreationDate();
        this.expiryDate = client.getExpiryDate();
        this.authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("CLIENT"));
        this.status = client.getStatus();
        this.client = true;
    }

    public static Profile create(Client client) {
        return create(client, false);
    }

    public static Profile create(Client client, boolean includePassword) {
        Profile profile = new Profile(client);
        if (includePassword) {
            profile.setPassword(client.getClientSecret());
        }
        return profile;
    }

    public static Profile create(UserDetails userDetails) {
        if (userDetails instanceof User) {
            return new Profile((User) userDetails);
        } else if (userDetails instanceof Client) {
            return new Profile((Client) userDetails);
        } else {
            return (Profile) userDetails;
        }
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
    public static class SimpleGrantedAuthority implements GrantedAuthority {
		private static final long serialVersionUID = -5690245860071067474L;
		private String authority;
    }
}
