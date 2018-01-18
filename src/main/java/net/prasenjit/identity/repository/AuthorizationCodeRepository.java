package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {
    Optional<AuthorizationCode> findByAuthorizationCode(String code);
}
