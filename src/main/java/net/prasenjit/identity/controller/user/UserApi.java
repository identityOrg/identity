package net.prasenjit.identity.controller.user;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.User;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Api(value = "User", tags = "user", description = "API's for user related operations")
public interface UserApi {

    @ApiOperation(value = "Search User", notes = "Search a user with any user attribute")
    List<User> searchClient(@ModelAttribute User client);

    @ApiOperation(value = "Find User", notes = "Find a client with username")
    User findClient(@PathVariable(value = "username") String clientId);

    @ApiOperation(value = "Update User", notes = "Update a user attributes")
    User update(@RequestBody User client);

    @ApiOperation(value = "Create User", notes = "Create a user, user is created is disabled state.")
    User create(@RequestBody User client);
}
