package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.exception.OperationIgnoredException;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final IdentityProperties identityProperties;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findById(s);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new UsernameNotFoundException("user not found");
        }
    }

    @Transactional
    public User createUser(User user) {
        Optional<User> optionalUser = userRepository.findById(user.getUsername());
        if (optionalUser.isPresent()) {
            throw new ConflictException("User already exist.");
        }
        user.setStatus(Status.LOCKED);
        LocalDateTime now = LocalDateTime.now();
        user.setPasswordExpiryDate(now.plus(identityProperties.getUserPasswordValidity()));
        user.setCreationDate(now);
        user.setAdmin(false);
        user.setPassword(RandomStringUtils.randomAlphanumeric(20)); // unknown password to create disabled user

        return userRepository.saveAndFlush(user);
    }

    @Transactional
    public User updateUser(User user) {
        Optional<User> optionalUser = userRepository.findById(user.getUsername());
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        }
        User savedUser = optionalUser.get();
        savedUser.setFirstName(user.getFirstName());
        savedUser.setLastName(user.getLastName());

        return savedUser;
    }

    @Transactional
    public User changeStatus(String username, Status status, String password) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else if (optionalUser.get().getStatus() == status) {
            throw new OperationIgnoredException("Status not changed");
        } else {
            optionalUser.get().setStatus(status);
            if (status == Status.ACTIVE) {
                Assert.notNull(password, "Password is required to activate user.");
                optionalUser.get().setPassword(passwordEncoder.encode(password));
            }
        }
        return optionalUser.get();
    }

    @Transactional
    public User changePassword(String username, String oldPassword, String newPassword) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            if (passwordEncoder.matches(oldPassword, optionalUser.get().getPassword())) {
                optionalUser.get().setPassword(passwordEncoder.encode(newPassword));
            } else {
                throw new InvalidRequestException("Old password doesnt match");
            }
        }
        return optionalUser.get();
    }
}
