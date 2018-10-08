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

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_E2E_KEY")
@IdClass(E2EKey.KeyId.class)
public class E2EKey {
    @Id
    @Column(name = "ASSOCIATION", nullable = false, length = 256)
    private String association;

    @Id
    @Column(name = "USER_TYPE", nullable = false, length = 10)
    @Enumerated(value = EnumType.STRING)
    private UserType userType;

    @Lob
    @Column(name = "CURRENT_PRIVATE_KEY", nullable = false)
    private String currentPrivateKey;

    @Lob
    @Column(name = "CURRENT_PUBLIC_KEY", nullable = false)
    private String currentPublicKey;

    @Lob
    @Column(name = "OLD_PRIVATE_KEY")
    private String oldPrivateKey;

    @Lob
    @Column(name = "OLD_PUBLIC_KEY")
    private String oldPublicKey;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    public boolean isValid(Duration validity) {
        return creationDate.plus(validity).isAfter(LocalDateTime.now());
    }

    public enum UserType {
        USER, CLIENT
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class KeyId implements Serializable {
		private static final long serialVersionUID = -1630505153203532266L;

		@Column(name = "ASSOCIATION", nullable = false, length = 256)
        private String association;

        @Column(name = "USER_TYPE", nullable = false, length = 10)
        @Enumerated(value = EnumType.STRING)
        private UserType userType;
    }
}
