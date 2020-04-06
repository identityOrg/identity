package net.prasenjit.identity.controller.claim;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.prasenjit.identity.entity.scope.ClaimEntity;

import java.util.List;

@Tag(name = "claim", description = "API's for claim related operations")
public interface ClaimApi {
    @Operation(summary = "Create Claim", description = "Create a new claim.")
    ClaimEntity create(ClaimEntity scope);

    @Operation(summary = "Update claim", description = "Update a claim.")
    ClaimEntity update(Integer claimId, ClaimEntity scope);

    @Operation(summary = "Find claim", description = "Find a claim.")
    ClaimEntity findScope(Integer claimId);

    @Operation(summary = "Find all claim", description = "Find all claim.")
    List<ClaimEntity> findAll();
}
