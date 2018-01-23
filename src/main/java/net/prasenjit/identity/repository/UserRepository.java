package net.prasenjit.identity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import net.prasenjit.identity.entity.User;

public interface UserRepository extends JpaRepository<User, String> {
}
