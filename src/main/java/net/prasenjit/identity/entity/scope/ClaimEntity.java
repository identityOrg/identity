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

package net.prasenjit.identity.entity.scope;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "T_CLAIM")
public class ClaimEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.TABLE)
    @Column(name = "CLAIM_ID")
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(name = "TYPE", length = 20, nullable = false)
    private ClaimType claimType;

    @Column(name = "STANDARD_ATTRIBUTE", length = 256)
    private String standardAttribute;
}
