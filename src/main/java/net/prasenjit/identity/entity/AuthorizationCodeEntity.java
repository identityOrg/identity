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
import org.springframework.util.StringUtils;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
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

    @Column(name = "CLIENT_ID", length = 50, nullable = false)
    private String clientId;

    @Column(name = "SCOPE", length = 500, nullable = false)
    private String scope;

    @Column(name = "STATE", length = 50)
    private String state;

    @Column(name = "CHALLENGE", length = 200)
    private String challenge;

    @Column(name = "CHALLENGE_METHOD", length = 20)
    private String challengeMethod;

    @Column(name = "USED", nullable = false)
    private boolean used;

    @Column(name = "LOGIN_DATE", nullable = false)
    private LocalDateTime loginDate;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    @Column(name = "OPEN_ID", nullable = false)
    private boolean openId;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate);
    }

    public boolean isChallengeAvailable() {
        if (StringUtils.hasText(challenge) && StringUtils.hasText(challengeMethod)) {
            return true;
        } else {
            return false;
        }
    }
}
