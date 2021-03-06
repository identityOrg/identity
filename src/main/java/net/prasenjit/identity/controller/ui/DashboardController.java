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

package net.prasenjit.identity.controller.ui;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.ui.UserInfoModify;
import net.prasenjit.identity.repository.AuditEventRepository;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import net.prasenjit.identity.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.validation.Valid;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class DashboardController {

    private final UserRepository userRepository;
    private final AuditEventRepository eventRepository;
    private final UserService userService;

    @GetMapping("/")
    public String dashboard(Authentication principal, Model model, Pageable pageable) {
        Optional<User> optionalUser = userRepository.findById(principal.getName());
        if (optionalUser.isPresent()) {
            UserAuthenticationToken token = (UserAuthenticationToken) principal;
            model.addAttribute("user", optionalUser.get());
            model.addAttribute("userInfo", optionalUser.get().getUserInfo());
            model.addAttribute("loginTime", token.getLoginTime());
            boolean admin = token.getAuthorities().stream().anyMatch(ga -> ga.getAuthority().equals("ADMIN"));
            model.addAttribute("admin", admin);
            findAudits(pageable, model);
            return "dashboard";
        }
        throw new ItemNotFoundException("User not found");
    }

    private void findAudits(Pageable pageable, Model model) {
        Page<AuditEvent> events = eventRepository.findByDisplayLevelGreaterThan(-5, pageable);
        model.addAttribute("events", events);
    }

    @PostMapping("/")
    public String modifyProfile(Authentication principal, @ModelAttribute @Valid UserInfoModify userInfoModify) {
        userService.modifyUser(principal.getName(), userInfoModify);
        return "redirect:/";
    }
}
