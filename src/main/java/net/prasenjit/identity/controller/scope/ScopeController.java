package net.prasenjit.identity.controller.scope;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.config.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Scope;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.scope.UpdateScopeRequest;
import net.prasenjit.identity.repository.ScopeRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@SwaggerDocumented
@RequiredArgsConstructor
@RequestMapping(value = "api/scope", produces = MediaType.APPLICATION_JSON_VALUE)
public class ScopeController implements ScopeApi {

    private final ScopeRepository scopeRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public Scope create(@RequestBody @Valid Scope scope) {
        Optional<Scope> scopeOptional = scopeRepository.findById(scope.getScopeId());
        if (scopeOptional.isPresent()) {
            throw new ConflictException("Scope already present");
        }

        CreateEvent csEvent = new CreateEvent(this, ResourceType.SCOPE, scope.getScopeId());
        eventPublisher.publishEvent(csEvent);

        return scopeRepository.saveAndFlush(scope);
    }

    @Override
    @PutMapping(value = "{scopeId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Scope update(@PathVariable("scopeId") String scopeId, @RequestBody @Valid UpdateScopeRequest request) {
        Optional<Scope> scopeOptional = scopeRepository.findById(scopeId);
        if (!scopeOptional.isPresent()) {
            throw new ItemNotFoundException("Scope not exist");
        }
        Scope scope = scopeOptional.get();
        scope.setScopeName(request.getScopeName());

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.SCOPE, scopeId);
        eventPublisher.publishEvent(csEvent);

        return scopeRepository.saveAndFlush(scope);
    }

    @Override
    @GetMapping(value = "{scopeId}")
    public Scope findScope(@PathVariable("scopeId") String scopeId) {
        Optional<Scope> scopeOptional = scopeRepository.findById(scopeId);
        if (!scopeOptional.isPresent()) {
            throw new ItemNotFoundException("Scope not found");
        }
        return scopeOptional.get();
    }

    @Override
    @GetMapping
    public List<Scope> findAll() {
        return scopeRepository.findAll();
    }
}
