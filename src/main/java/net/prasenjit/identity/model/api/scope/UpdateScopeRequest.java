package net.prasenjit.identity.model.api.scope;

import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class UpdateScopeRequest {
    @NotEmpty
    private String scopeName;
}
