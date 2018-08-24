package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.ScopeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScopeRepository extends JpaRepository<ScopeEntity, String> {
}
