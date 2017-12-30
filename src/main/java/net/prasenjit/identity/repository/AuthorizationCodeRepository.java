package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {
}
