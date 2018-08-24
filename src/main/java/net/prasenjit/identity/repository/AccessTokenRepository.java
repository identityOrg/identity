package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AccessTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccessTokenRepository extends JpaRepository<AccessTokenEntity, String> {
}
