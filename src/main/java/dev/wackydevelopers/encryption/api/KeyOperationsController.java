package dev.wackydevelopers.encryption.api;

import dev.wackydevelopers.encryption.service.KeyRotationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static dev.wackydevelopers.encryption.api.SecuredEntityApiModels.*;

@RestController
@RequestMapping("/v1/admin/keys")
public class KeyOperationsController {
    
    private final KeyRotationService keyRotationService;

    public KeyOperationsController(KeyRotationService keyRotationService) {
        this.keyRotationService = keyRotationService;
    }

    @PostMapping("/kek/rotate")
    public ResponseEntity<KeyRotationPlanResponse> rotateKek(@RequestBody(required = false) RotateKekRequest request) {
        String reason = request == null ? "rotation requested" : request.reason();
        KeyRotationService.KeyRotationPlan plan = keyRotationService.rotateKek(reason);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new KeyRotationPlanResponse(toDto(plan)));
    }

    @PostMapping("/bik/rotate")
    public ResponseEntity<KeyRotationPlanResponse> rotateBik(@RequestBody RotateBikRequest request) {
        boolean requireDryRun = request.requireDryRun() != null && request.requireDryRun();
        KeyRotationService.KeyRotationPlan plan = keyRotationService.rotateBik(request.reason(), requireDryRun);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new KeyRotationPlanResponse(toDto(plan)));
    }

    @GetMapping("/rotations/{rotationId}")
    public ResponseEntity<KeyRotationPlanResponse> getKeyRotationPlan(@PathVariable("rotationId") String rotationId) {
        KeyRotationService.KeyRotationPlan plan = keyRotationService.getPlan(rotationId);
        return ResponseEntity.ok(new KeyRotationPlanResponse(toDto(plan)));
    }

    private KeyRotationPlanDto toDto(KeyRotationService.KeyRotationPlan plan) {
        return new KeyRotationPlanDto(
                plan.rotationId(),
                plan.keyType(),
                plan.requestedAt(),
                plan.executedAt(),
                plan.status(),
                plan.rollbackRequired());
    }
}
