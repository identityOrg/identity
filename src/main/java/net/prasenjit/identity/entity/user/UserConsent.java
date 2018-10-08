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

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_USER_CONSENT")
@IdClass(UserConsent.UserConsentPK.class)
public class UserConsent {
    @Id
    @Column(name = "USERNAME")
    private String username;
    @Id
    @Column(name = "CLIENT_ID")
    private String clientID;

    @Column(name = "SCOPES")
    private String scopes;

    @Column(name = "APPRIVAL_DATE")
    private LocalDateTime approvalDate;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserConsentPK implements Serializable {
		private static final long serialVersionUID = 7839471339955798852L;
		@Column(name = "USERNAME")
        private String username;
        @Column(name = "CLIENT_ID")
        private String clientID;
    }
}
