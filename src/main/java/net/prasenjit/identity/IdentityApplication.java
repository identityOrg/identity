package net.prasenjit.identity;

import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.LocalDateTime;

@SpringBootApplication
public class IdentityApplication implements ApplicationRunner {

    @Autowired
    @Qualifier("client-password")
    public TextEncryptor textEncryptor;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ClientRepository clientRepository;
    private PasswordEncoder userPasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public static void main(String[] args) {
        SpringApplication.run(IdentityApplication.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {

        User admin = createAdmin("admin");
        userRepository.saveAndFlush(admin);

        Client client = createClient("client", true);
        clientRepository.saveAndFlush(client);

        client = createClient("insecure", false);
        clientRepository.saveAndFlush(client);

    }

    private Client createClient(String clientId, boolean secure) {
        Client client = new Client();
        client.setClientId(clientId);
        if (secure)
            client.setClientSecret(textEncryptor.encrypt(clientId));
        client.setCreationDate(LocalDateTime.now());
        client.setStatus(Status.ACTIVE);
        client.setClientName("Test Client");
        client.setApprovedScopes("scope1");
        client.setRedirectUri("http://localhost:9090/login/oauth2/code/identity");
        client.setAccessTokenValidity(Duration.ofMinutes(30));
        client.setRefreshTokenValidity(Duration.ofHours(2));
        return client;
    }

    private User createAdmin(String username) {
        User user = new User();
        user.setAdmin(true);
        user.setCreationDate(LocalDateTime.now());
        user.setUsername(username);
        user.setPassword(userPasswordEncoder.encode(username));
        user.setStatus(Status.ACTIVE);
        user.setPasswordExpiryDate(LocalDateTime.now().plusDays(2));
        return user;
    }
}
