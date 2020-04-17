package net.prasenjit.identity.model.api.scope;

import lombok.Getter;
import lombok.Setter;
import net.prasenjit.identity.entity.scope.ClaimEntity;
import net.prasenjit.identity.entity.scope.ScopeEntity;

import java.util.Set;

public class ScopeDTO extends ScopeEntity {

    @Getter
    @Setter
    private Set<ClaimEntity> attachedClaims;

    public ScopeDTO(ScopeEntity scopeEntity) {
        setScopeName(scopeEntity.getScopeName());
        setScopeId(scopeEntity.getScopeId());
        setCustom(scopeEntity.getCustom());
        attachedClaims = scopeEntity.getClaims();
    }

}
