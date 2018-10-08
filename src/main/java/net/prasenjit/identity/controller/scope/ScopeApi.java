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

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.ScopeEntity;
import net.prasenjit.identity.model.api.scope.UpdateScopeRequest;

import java.util.List;

@Api(value = "Scope", tags = "scope", description = "API's for scope related operations")
public interface ScopeApi {

    @ApiOperation(value = "Create Scope", notes = "Create a new scope.")
    ScopeEntity create(ScopeEntity scope);

    @ApiOperation(value = "Update Scope", notes = "Update a scope.")
    ScopeEntity update(String scopeId, UpdateScopeRequest scope);

    @ApiOperation(value = "Find Scope", notes = "Find a scope.")
    ScopeEntity findScope(String scopeId);

    @ApiOperation(value = "Find all", notes = "Find all scopes.")
    List<ScopeEntity> findAll();
}
