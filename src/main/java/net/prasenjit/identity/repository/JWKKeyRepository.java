package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.JWKKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface JWKKeyRepository extends JpaRepository<JWKKey, Long> {
    //List<JWKKey> findFirst5OrderByCreationDateDesc();
}
