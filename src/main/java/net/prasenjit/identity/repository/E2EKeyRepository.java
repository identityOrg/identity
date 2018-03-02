package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.E2EKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface E2EKeyRepository extends JpaRepository<E2EKey, E2EKey.KeyId> {
}
