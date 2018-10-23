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

package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.model.ui.ChangePassword;
import net.prasenjit.identity.security.JWTRememberMe;
import net.prasenjit.identity.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Controller
@RequiredArgsConstructor
public class ChangePasswordController {

    private final UserService userService;
    private final JWTRememberMe jwtRememberMe;

    @GetMapping("change-password")
    public String displayUI(HttpSession httpSession, Model model) {
        String username = (String) httpSession.getAttribute("password-change-forced-for");
        if (StringUtils.hasText(username)) {
            model.addAttribute("forced", true);
            model.addAttribute("username", username);
        } else {
            if (!SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
                return "redirect:/";
            }
        }
        return "change_password";
    }

    @PostMapping("change-password")
    public String changePassword(@ModelAttribute @Valid ChangePassword changePassword, HttpSession httpSession,
                                 HttpServletRequest request, HttpServletResponse response, Model model) {
        String username = (String) httpSession.getAttribute("password-change-forced-for");
        try {
            if (StringUtils.hasText(username)) {
                userService.changePassword(username, changePassword.getOldPassword(), changePassword.getNewPassword());
                String requestURI = (String) httpSession.getAttribute(PREVIOUS_URL);
                if (requestURI != null) {
                    return "redirect:" + requestURI;
                } else {
                    return "redirect:/";
                }
            } else {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (!authentication.isAuthenticated()) {
                    return "redirect:/";
                } else {
                    username = authentication.getName();
                    userService.changePassword(username, changePassword.getOldPassword(), changePassword.getNewPassword());
                    jwtRememberMe.loginSuccess(request, response, authentication);
                    return "redirect:/";
                }
            }
        } catch (InvalidRequestException ex) {
            model.addAttribute("error", ex.getMessage());
            return "change_password";
        }
    }
}
