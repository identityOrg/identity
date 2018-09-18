package net.prasenjit.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import net.prasenjit.identity.entity.JWKKey;

public interface JWKKeyRepository extends JpaRepository<JWKKey, Long> {
    //List<JWKKey> findFirst5OrderByCreationDateDesc();
}
