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
