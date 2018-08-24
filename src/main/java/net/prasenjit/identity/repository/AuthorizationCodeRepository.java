package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuthorizationCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCodeEntity, Long> {
    Optional<AuthorizationCodeEntity> findByAuthorizationCode(String code);
}
