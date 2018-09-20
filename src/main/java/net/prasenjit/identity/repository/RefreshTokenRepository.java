package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.stream.Stream;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {
    Stream<RefreshTokenEntity> findByActiveTrueAndParentRefreshTokenEquals(String parentRefreshToken);
}
