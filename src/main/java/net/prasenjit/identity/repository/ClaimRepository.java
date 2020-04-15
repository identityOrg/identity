package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.scope.ClaimEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClaimRepository extends JpaRepository<ClaimEntity, Integer> {
    ClaimEntity findByStandardAttribute(String standardAttribute);
}
