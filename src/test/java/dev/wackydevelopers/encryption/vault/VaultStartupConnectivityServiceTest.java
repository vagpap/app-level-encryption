package dev.wackydevelopers.encryption.vault;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class VaultStartupConnectivityServiceTest {

    @Test
    void shouldSucceedAfterTransientFailuresWithinRetryBudget() {
        AtomicInteger attempts = new AtomicInteger(0);
        VaultConnectivityProbe probe = () -> {
            if (attempts.incrementAndGet() < 3) {
                throw new RuntimeException("temporary vault unavailability");
            }
        };

        List<Long> delays = new ArrayList<>();
        Sleeper sleeper = delays::add;

        VaultRetryPolicy policy = new VaultRetryPolicy(5, 10, 2.0d, 100);
        VaultStartupConnectivityService service = new VaultStartupConnectivityService(probe, policy, sleeper);

        assertDoesNotThrow(service::ensureConnectivityOrThrow);
        assertEquals(3, attempts.get());
        assertEquals(List.of(10L, 20L), delays);
    }

    @Test
    void shouldFailWithActionableDiagnosticsAfterMaxAttempts() {
        AtomicInteger attempts = new AtomicInteger(0);
        VaultConnectivityProbe probe = () -> {
            attempts.incrementAndGet();
            throw new RuntimeException("vault is down");
        };

        VaultRetryPolicy policy = new VaultRetryPolicy(3, 5, 2.0d, 50);
        VaultStartupConnectivityService service = new VaultStartupConnectivityService(probe, policy, millis -> {
        });

        VaultStartupException ex = assertThrows(VaultStartupException.class, service::ensureConnectivityOrThrow);

        assertEquals(3, attempts.get());
        assertTrue(ex.getMessage().contains("Unable to establish Vault connectivity"));
        assertTrue(ex.getMessage().contains("VAULT_ADDR/VAULT_TOKEN"));
        assertTrue(ex.getMessage().contains("health status"));
        assertTrue(ex.getMessage().contains("network/TLS"));
    }

    @Test
    void computeDelayShouldRespectExponentialBackoffAndCap() {
        VaultRetryPolicy policy = new VaultRetryPolicy(5, 10, 2.0d, 25);
        VaultStartupConnectivityService service = new VaultStartupConnectivityService(() -> {
        }, policy, millis -> {
        });

        assertEquals(10L, service.computeDelayMillis(1));
        assertEquals(20L, service.computeDelayMillis(2));
        assertEquals(25L, service.computeDelayMillis(3));
        assertEquals(25L, service.computeDelayMillis(4));
    }
}
