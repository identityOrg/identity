package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AccessTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.stream.Stream;

public interface AccessTokenRepository extends JpaRepository<AccessTokenEntity, String> {
    Stream<AccessTokenEntity> findByActiveTrueAndRefreshTokenEquals(String refreshToken);
}
