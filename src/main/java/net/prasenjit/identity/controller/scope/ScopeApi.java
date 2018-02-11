package net.prasenjit.identity.controller.scope;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.Scope;
import net.prasenjit.identity.model.api.scope.UpdateScopeRequest;

import java.util.List;

@Api(value = "Scope", tags = "scope", description = "API's for scope related operations")
public interface ScopeApi {

    @ApiOperation(value = "Create Scope", notes = "Create a new scope.")
    Scope create(Scope scope);

    @ApiOperation(value = "Update Scope", notes = "Update a scope.")
    Scope update(String scopeId, UpdateScopeRequest scope);

    @ApiOperation(value = "Find Scope", notes = "Find a scope.")
    Scope findScope(String scopeId);

    @ApiOperation(value = "Find all", notes = "Find all scopes.")
    List<Scope> findAll();
}
