package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.Scope;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScopeRepository extends JpaRepository<Scope, Long> {
}
