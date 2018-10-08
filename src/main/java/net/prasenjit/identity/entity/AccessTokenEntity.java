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

package net.prasenjit.identity.entity;

import lombok.Data;
import net.prasenjit.identity.entity.converter.AbstractJsonConverter;
import net.prasenjit.identity.model.Profile;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_ACCESS_TOKEN")
public class AccessTokenEntity {
    @Id
    @Column(name = "ACCESS_TOKEN", length = 50, nullable = false)
    private String assessToken;

    @Column(name = "REFRESH_TOKEN", length = 50)
    private String refreshToken;

    @Column(name = "USERNAME", length = 50, nullable = false)
    private String username;

    @Column(name = "ACTIVE", nullable = false)
    private boolean active = true;

    @Lob
    @Column(name = "USER_PROFILE", nullable = false)
    @Convert(converter = AbstractJsonConverter.ProfileConverter.class)
    private Profile userProfile;

    @Column(name = "CLIENT_ID", length = 50, nullable = false)
    private String clientId;

    @Column(name = "SCOPE", length = 500, nullable = false)
    private String scope;

    @Column(name = "LOGIN_DATE", nullable = false)
    private LocalDateTime loginDate;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate) && active;
    }
}
