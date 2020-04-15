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

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.util.Set;

@Data
@Entity
@Table(name = "T_SCOPE")
public class ScopeEntity implements Serializable {
    private static final long serialVersionUID = 648424861320420292L;

    @Id
    @Column(name = "SCOPE_ID", length = 50, nullable = false, unique = true)
    @NotEmpty
    private String scopeId;

    @Column(name = "SCOPE_NAME", length = 50, nullable = false, unique = true)
    private String scopeName;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "T_SCOPE_CLAIM",
            joinColumns = @JoinColumn(name = "SCOPE_ID", referencedColumnName = "SCOPE_ID"),
            inverseJoinColumns = @JoinColumn(name = "CLAIM_ID", referencedColumnName = "CLAIM_ID"))
    private Set<ClaimEntity> claims;

}
