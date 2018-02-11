package net.prasenjit.identity.controller.user;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.ItemNotFoundException;
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
    public List<User> searchClient(@ModelAttribute User client) {
        Example<User> clientExample = Example.of(client);
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
    @PutMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User update(@RequestBody User user) {
        return userService.updateUser(user);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public User create(@RequestBody User user) {
        return userService.createUser(user);
    }
}
