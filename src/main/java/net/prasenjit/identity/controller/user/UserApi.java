package net.prasenjit.identity.controller.user;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.model.api.*;

import java.util.List;

@Api(value = "User", tags = "user", description = "API's for user related operations")
public interface UserApi {

    @ApiOperation(value = "Search User", notes = "Search a user with any user attribute")
    List<User> searchClient(SearchUserRequest request);

    @ApiOperation(value = "Find User", notes = "Find a client with username")
    User findClient(String clientId);

    @ApiOperation(value = "Update User", notes = "Update a user attributes")
    User update(String username, UpdateUserRequest request);

    @ApiOperation(value = "Create User", notes = "Create a user, user is created is disabled state.")
    User create(CreateUserRequest request);

    @ApiOperation(value = "Change Status", notes = "Change status of a user.")
    User status(String username, StatusUserRequest request);

    @ApiOperation(value = "Change password", notes = "Change password of a user.")
    User password(String username, PasswordUserRequest request);
}
