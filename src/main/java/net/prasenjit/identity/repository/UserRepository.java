package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
