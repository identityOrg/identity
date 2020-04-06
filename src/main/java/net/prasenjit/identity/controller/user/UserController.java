/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.controller.user;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.user.User;
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
@RequiredArgsConstructor
@RequestMapping(value = "api/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController implements UserApi {

    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    @GetMapping
    public List<User> searchUser(@ModelAttribute SearchUserRequest request) {
        User user = new User();
        user.setLocked(request.getLocked());
        user.setActive(request.getActive());
        user.setAdmin(request.getAdmin());
        user.setUsername(request.getUsername());

        Example<User> clientExample = Example.of(user);
        return userRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{username}")
    public UserDTO findUser(@PathVariable(value = "username") String username) {
        Optional<User> userOptional = userRepository.findById(username);
        if (userOptional.isPresent()) {
            return new UserDTO(userOptional.get());
        } else {
            throw new ItemNotFoundException("User not found");
        }
    }

    @Override
    @PutMapping(value = "{username}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public UserDTO update(@PathVariable(value = "username") String username,
                          @RequestBody @Valid UpdateUserRequest request) {
        request.setUsername(username);
        User user = userService.updateUser(request);
        return new UserDTO(user);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public UserDTO create(@RequestBody @Valid CreateUserRequest request) {
        User user = userService.createUser(request);
        return new UserDTO(user);
    }

    @Override
    @PostMapping(value = "{username}/status", consumes = MediaType.APPLICATION_JSON_VALUE)
    public UserDTO status(@PathVariable(value = "username") String username,
                          @RequestBody @Valid StatusUserRequest request) {
        User user = userService.changeStatus(username, request.getStatus(), request.getPassword());
        return new UserDTO(user);
    }

    @Override
    @PostMapping(value = "{username}/password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public UserDTO password(@PathVariable(value = "username") String username,
                            @RequestBody @Valid PasswordUserRequest request) {
        User user = userService.changePassword(username, request.getOldPassword(), request.getNewPassword());
        return new UserDTO(user);
    }
}
