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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.model.api.user.*;

import java.util.List;

@Tag(name = "user", description = "API's for user related operations")
public interface UserApi {

    @Operation(summary = "Search User", description = "Search a user with any user attribute")
    List<User> searchUser(SearchUserRequest request);

    @Operation(summary = "Find User", description = "Find a user with username")
    User findUser(String clientId);

    @Operation(summary = "Update User", description = "Update a user attributes")
    User update(String username, UpdateUserRequest request);

    @Operation(summary = "Create User", description = "Create a user, user is created is disabled state.")
    User create(CreateUserRequest request);

    @Operation(summary = "Change Status", description = "Change status of a user.")
    User status(String username, StatusUserRequest request);

    @Operation(summary = "Change password", description = "Change password of a user.")
    User password(String username, PasswordUserRequest request);
}
