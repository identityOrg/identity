package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {
}
