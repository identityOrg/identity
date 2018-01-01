package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.repository.ClientRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ClientService implements UserDetailsService {

    private final ClientRepository clientRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<Client> client = clientRepository.findById(s);
        if (client.isPresent()) {
            return client.get();
        } else {
            throw new UsernameNotFoundException("client not found");
        }
    }
}
