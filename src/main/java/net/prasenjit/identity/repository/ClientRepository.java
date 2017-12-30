package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, String> {
}
