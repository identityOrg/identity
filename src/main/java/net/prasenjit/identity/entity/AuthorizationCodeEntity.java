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

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import lombok.Data;
import net.prasenjit.identity.entity.converter.AbstractJsonConverter;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_AUTHORIZATION_CODE")
public class AuthorizationCodeEntity {
    @Id
    @Column(name = "AUTHORIZATION_CODE", length = 50, nullable = false, unique = true)
    private String authorizationCode;

    @Column(name = "RETURN_URL", length = 500)
    private String returnUrl;

    @Column(name = "USERNAME", length = 50, nullable = false)
    private String username;

    @Column(name = "SCOPE", length = 500, nullable = false)
    private String scope;

    @Column(name = "USED", nullable = false)
    private boolean used;

    @Column(name = "OPEN_ID", nullable = false)
    private boolean openId;

    @Lob
    @Column(name = "REQUEST", nullable = false)
    @Convert(converter = AbstractJsonConverter.AuthorizationRequestConverter.class)
    private AuthorizationRequest request;

    @Column(name = "LOGIN_DATE", nullable = false)
    private LocalDateTime loginDate;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate);
    }

    public boolean isChallengeAvailable() {
        return request != null && request.getCodeChallenge() != null && request.getCodeChallengeMethod() != null;
    }
}
