package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.E2EKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface E2EKeyRepository extends JpaRepository<E2EKey, E2EKey.KeyId> {
}
