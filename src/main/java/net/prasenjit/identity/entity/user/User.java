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

package net.prasenjit.identity.entity.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.Data;
import net.prasenjit.identity.entity.converter.UserInfoConverter;
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

	@Column(name = "LOCKED", nullable = false)
	private Boolean locked;

	@Column(name = "ACTIVE", nullable = false)
	private Boolean active;

	@Column(name = "CREATION_DATE", nullable = false)
	private LocalDateTime creationDate;

	@Column(name = "EXPIRY_DATE")
	private LocalDateTime expiryDate;

	@Column(name = "PASSWORD_EXPIRY_DATE", nullable = false)
	private LocalDateTime passwordExpiryDate;

	@Column(name = "ADMIN", nullable = false)
	private Boolean admin;

	@Lob
	@Column(name = "PROFILE", nullable = false)
	@Convert(converter = UserInfoConverter.class)
	@JsonIgnore
	private UserInfo userInfo;

	@Override
	@JsonIgnore
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
		return !locked;
	}

	@Override
	@JsonIgnore
	public boolean isCredentialsNonExpired() {
		return passwordExpiryDate == null || passwordExpiryDate.isAfter(LocalDateTime.now());
	}

	@Override
	@JsonIgnore
	public boolean isEnabled() {
		return active;
	}

	@JsonIgnore
	public boolean isValid() {
		return isAccountNonExpired() && isAccountNonLocked() && isEnabled();
	}

}
