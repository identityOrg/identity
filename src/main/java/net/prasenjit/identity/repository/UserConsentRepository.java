package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserConsentRepository extends JpaRepository<UserConsent, UserConsent.UserConsentPK> {
}
