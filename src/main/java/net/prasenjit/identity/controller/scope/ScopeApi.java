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

package net.prasenjit.identity.controller.scope;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.prasenjit.identity.entity.scope.ScopeEntity;
import net.prasenjit.identity.model.api.scope.ScopeDTO;
import net.prasenjit.identity.model.api.scope.UpdateScopeRequest;

import java.util.List;

@Tag(name = "scope", description = "API's for scope related operations")
public interface ScopeApi {

    @Operation(summary = "Create Scope", description = "Create a new scope.")
    ScopeDTO create(ScopeEntity scope);

    @Operation(summary = "Update Scope", description = "Update a scope.")
    ScopeDTO update(String scopeId, UpdateScopeRequest scope);

    @Operation(summary = "Add claim", description = "Add claim to scope.")
    ScopeDTO addClaim(String scopeId, Integer claimId);

    @Operation(summary = "Remove claim", description = "Remove claim from scope.")
    ScopeDTO removeClaim(String scopeId, Integer claimId);

    @Operation(summary = "Find Scope", description = "Find a scope.")
    ScopeDTO findScope(String scopeId);

    @Operation(summary = "Find all", description = "Find all scopes.")
    List<ScopeEntity> findAll();
}
