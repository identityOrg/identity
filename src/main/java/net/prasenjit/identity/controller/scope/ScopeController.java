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

package net.prasenjit.identity.controller.scope;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.scope.ClaimEntity;
import net.prasenjit.identity.entity.scope.ScopeEntity;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.scope.ScopeDTO;
import net.prasenjit.identity.model.api.scope.UpdateScopeRequest;
import net.prasenjit.identity.repository.ClaimRepository;
import net.prasenjit.identity.repository.ScopeRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "api/scope", produces = MediaType.APPLICATION_JSON_VALUE)
public class ScopeController implements ScopeApi {

    private final ScopeRepository scopeRepository;
    private final ClaimRepository claimRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ScopeDTO create(@RequestBody @Valid ScopeEntity scope) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scope.getScopeId());
        if (scopeOptional.isPresent()) {
            throw new ConflictException("Scope already present");
        }
        scope.setCustom(true);

        CreateEvent csEvent = new CreateEvent(this, ResourceType.SCOPE, scope.getScopeId());
        eventPublisher.publishEvent(csEvent);

        return new ScopeDTO(scopeRepository.saveAndFlush(scope));
    }

    @Override
    @Transactional
    @PutMapping(value = "{scopeId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ScopeDTO update(@PathVariable("scopeId") String scopeId, @RequestBody @Valid UpdateScopeRequest request) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scopeId);
        if (scopeOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not exist");
        }
        ScopeEntity scope = scopeOptional.get();
        scope.setScopeName(request.getScopeName());

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.SCOPE, scopeId);
        eventPublisher.publishEvent(csEvent);

        return new ScopeDTO(scopeRepository.saveAndFlush(scope));
    }

    @Override
    @Transactional
    @PatchMapping(value = "{scopeId}/add-claim/{claimId}")
    public ScopeDTO addClaim(@PathVariable("scopeId") String scopeId, @PathVariable("claimId") Integer claimId) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scopeId);
        if (scopeOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not exist");
        }
        ScopeEntity scope = scopeOptional.get();
        Optional<ClaimEntity> newClaim = claimRepository.findById(claimId);
        if (newClaim.isEmpty()) {
            throw new ItemNotFoundException("Claim not exist");
        }
        ClaimEntity claim = new ClaimEntity();
        claim.setId(claimId);
        scope.getClaims().add(claim);

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.SCOPE, scopeId);
        eventPublisher.publishEvent(csEvent);

        return new ScopeDTO(scopeRepository.saveAndFlush(scope));
    }

    @Override
    @Transactional
    @PatchMapping(value = "{scopeId}/remove-claim/{claimId}")
    public ScopeDTO removeClaim(@PathVariable("scopeId") String scopeId, @PathVariable("claimId") Integer claimId) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scopeId);
        if (scopeOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not exist");
        }
        ScopeEntity scope = scopeOptional.get();
        Optional<ClaimEntity> found = scope.getClaims().stream()
                .filter(claimEntity -> claimEntity.getId().equals(claimId))
                .findFirst();
        if (found.isPresent()) {
            scope.getClaims().remove(found.get());

            UpdateEvent csEvent = new UpdateEvent(this, ResourceType.SCOPE, scopeId);
            eventPublisher.publishEvent(csEvent);
            return new ScopeDTO(scopeRepository.saveAndFlush(scope));
        } else {
            return new ScopeDTO(scope);
        }

    }

    @Override
    @Transactional(readOnly = true)
    @GetMapping(value = "{scopeId}")
    public ScopeDTO findScope(@PathVariable("scopeId") String scopeId) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scopeId);
        if (scopeOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not found");
        }
        return new ScopeDTO(scopeOptional.get());
    }

    @Override
    @GetMapping
    public List<ScopeEntity> findAll() {
        return scopeRepository.findAll();
    }

    @Override
    @Transactional
    @DeleteMapping(value = "{scopeId}")
    @ResponseStatus(code = HttpStatus.NO_CONTENT)
    public void deleteScope(@PathVariable("scopeId") String scopeId) {
        Optional<ScopeEntity> scopeOptional = scopeRepository.findById(scopeId);
        if (scopeOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not found");
        }
        ScopeEntity scope = scopeOptional.get();
        if (!scope.getCustom()) {
            throw new InvalidRequestException("Only custom scopes are allowed to delete");
        }

        scopeRepository.delete(scope);
    }
}
