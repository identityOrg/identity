package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.client.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, String> {
}
