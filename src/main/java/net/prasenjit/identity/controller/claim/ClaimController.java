package net.prasenjit.identity.controller.claim;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.scope.ClaimEntity;
import net.prasenjit.identity.entity.scope.ClaimType;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.repository.ClaimRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Example;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "api/claim", produces = MediaType.APPLICATION_JSON_VALUE)
public class ClaimController implements ClaimApi {

    private final ClaimRepository claimRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ClaimEntity create(@RequestBody ClaimEntity claim) {
        if (claimRepository.findByStandardAttribute(claim.getStandardAttribute()) != null) {
            throw new ConflictException("Claim already present with same standard attribute");
        }

        claim.setClaimType(ClaimType.NORMAL);
        claim.setCustom(true);

        CreateEvent csEvent = new CreateEvent(this, ResourceType.CLAIM, String.valueOf(claim.getId()));
        eventPublisher.publishEvent(csEvent);

        return claimRepository.saveAndFlush(claim);
    }

    @Override
    @Transactional
    @PutMapping(value = "{claimId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ClaimEntity update(@PathVariable("claimId") Integer claimId, @RequestBody ClaimEntity request) {
        Optional<ClaimEntity> claimOptional = claimRepository.findById(claimId);
        if (claimOptional.isEmpty() || !claimOptional.get().getCustom()) {
            throw new ItemNotFoundException("Claim not exist or not editable");
        }
        ClaimEntity claim = claimOptional.get();
        //claim.setClaimType(request.getClaimType());
        claim.setStandardAttribute(request.getStandardAttribute());
        claim.setDescription(request.getDescription());

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.CLAIM, String.valueOf(claimId));
        eventPublisher.publishEvent(csEvent);

        return claimRepository.saveAndFlush(claim);
    }

    @Override
    @Transactional(readOnly = true)
    @GetMapping(value = "{claimId}")
    public ClaimEntity findOne(@PathVariable("claimId") Integer claimId) {
        Optional<ClaimEntity> claimOptional = claimRepository.findById(claimId);
        if (claimOptional.isEmpty()) {
            throw new ItemNotFoundException("Scope not found");
        }
        return claimOptional.get();
    }

    @Override
    @GetMapping
    @Transactional(readOnly = true)
    public List<ClaimEntity> findAll(@ModelAttribute ClaimEntity claim) {
        claim.setId(null);
        Example<ClaimEntity> example = Example.of(claim);
        return claimRepository.findAll(example);
    }
}
