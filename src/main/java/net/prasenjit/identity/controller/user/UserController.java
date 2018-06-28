package net.prasenjit.identity.controller.user;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.user.*;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.service.UserService;
import org.springframework.data.domain.Example;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@SwaggerDocumented
@RequiredArgsConstructor
@RequestMapping(value = "api/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController implements UserApi {

    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    @GetMapping
    public List<User> searchClient(@ModelAttribute SearchUserRequest request) {
        User user = new User();
        user.setLocked(request.getLocked());
        user.setActive(request.getActive());
        user.setLastName(request.getLastName());
        user.setFirstName(request.getFirstName());
        user.setAdmin(request.getAdmin());
        user.setUsername(request.getUsername());

        Example<User> clientExample = Example.of(user);
        return userRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{username}")
    public User findClient(@PathVariable(value = "username") String username) {
        Optional<User> userOptional = userRepository.findById(username);
        if (userOptional.isPresent()) {
            return userOptional.get();
        } else {
            throw new ItemNotFoundException("User not found");
        }
    }

    @Override
    @PutMapping(value = "{username}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public User update(@PathVariable(value = "username") String username,
                       @RequestBody @Valid UpdateUserRequest request) {
        request.setUsername(username);
        return userService.updateUser(request);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public User create(@RequestBody @Valid CreateUserRequest request) {
        return userService.createUser(request);
    }

    @Override
    @PostMapping(value = "{username}/status", consumes = MediaType.APPLICATION_JSON_VALUE)
    public User status(@PathVariable(value = "username") String username,
                       @RequestBody @Valid StatusUserRequest request) {
        return userService.changeStatus(username, request.getStatus(), request.getPassword());
    }

    @Override
    @PostMapping(value = "{username}/password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public User password(@PathVariable(value = "username") String username,
                         @RequestBody @Valid PasswordUserRequest request) {
        return userService.changePassword(username, request.getOldPassword(), request.getNewPassword());
    }
}
