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

package net.prasenjit.identity.entity.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import lombok.Data;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.converter.MetadataConverter;

import javax.persistence.*;
import java.time.Duration;
import java.time.LocalDateTime;

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

    @Column(name = "ACCESS_TOKEN_VALIDITY", nullable = false)
    private Duration accessTokenValidity;

    @Column(name = "REFRESH_TOKEN_VALIDITY", nullable = false)
    private Duration refreshTokenValidity;

    @Lob
    @Column(name = "METADATA", nullable = false)
    @Convert(converter = MetadataConverter.class)
    private OIDCClientMetadata metadata;

    public boolean supportsGrant(GrantType grant) {
        return getMetadata().getGrantTypes().contains(grant);
    }

    public Scope getApprovedScopes() {
        return getMetadata().getScope();
    }

    public boolean isAccountNonExpired() {
        LocalDateTime now = LocalDateTime.now();
        if (now.isBefore(creationDate)) return false;
        return expiryDate == null || now.isBefore(expiryDate);
    }
}
