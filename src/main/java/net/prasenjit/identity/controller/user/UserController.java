package net.prasenjit.identity.controller.user;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.*;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.service.UserService;
import org.springframework.data.domain.Example;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@SwaggerDocumented
@RequiredArgsConstructor
@RequestMapping(value = "api/user")
public class UserController implements UserApi {

    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<User> searchClient(@ModelAttribute SearchUserRequest request) {
        User user = new User();
        user.setStatus(request.getStatus());
        user.setLastName(request.getLastName());
        user.setFirstName(request.getFirstName());
        user.setAdmin(request.isAdmin());
        user.setUsername(request.getUsername());

        Example<User> clientExample = Example.of(user);
        return userRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{username}", produces = MediaType.APPLICATION_JSON_VALUE)
    public User findClient(@PathVariable(value = "username") String username) {
        Optional<User> userOptional = userRepository.findById(username);
        if (userOptional.isPresent()) {
            return userOptional.get();
        } else {
            throw new ItemNotFoundException("User not found");
        }
    }

    @Override
    @PutMapping(value = "{username}", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User update(@PathVariable(value = "username") String username, @RequestBody UpdateUserRequest request) {
        request.setUsername(username);
        return userService.updateUser(request);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User create(@RequestBody CreateUserRequest request) {
        return userService.createUser(request);
    }

    @Override
    @PostMapping(value = "{username}/status", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User status(@PathVariable(value = "username") String username, @RequestBody StatusUserRequest request) {
        return userService.changeStatus(username, request.getStatus(), request.getPassword());
    }

    @Override
    @PostMapping(value = "{username}/password", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User password(@PathVariable(value = "username") String username, @RequestBody PasswordUserRequest request) {
        return userService.changePassword(username, request.getOldPassword(), request.getNewPassword());
    }
}
