package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccessTokenRepository extends JpaRepository<AccessToken, String> {
}
