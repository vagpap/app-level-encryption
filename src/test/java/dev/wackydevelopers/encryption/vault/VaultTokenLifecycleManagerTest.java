package dev.wackydevelopers.encryption.vault;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class VaultTokenLifecycleManagerTest {

    @Test
    void shouldRecordRenewalSuccessAndExposeLastStatus() {
        VaultTokenLeaseStatus status = new VaultTokenLeaseStatus("lease-1", Instant.now().plusSeconds(120), true, true);

        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger skipped = new AtomicInteger(0);
        AtomicInteger failure = new AtomicInteger(0);

        VaultTokenLifecycleManager manager = new VaultTokenLifecycleManager(
                () -> status,
                new MetricsCounter(success, skipped, failure)
        );

        VaultTokenLeaseStatus returned = manager.renewCycle();

        assertEquals(status, returned);
        assertEquals(status, manager.getLastStatus());
        assertEquals(1, success.get());
        assertEquals(0, skipped.get());
        assertEquals(0, failure.get());
    }

    @Test
    void shouldRecordSkippedWhenLeaseIsNotRenewable() {
        VaultTokenLeaseStatus status = new VaultTokenLeaseStatus("lease-2", Instant.now().plusSeconds(120), false, false);

        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger skipped = new AtomicInteger(0);
        AtomicInteger failure = new AtomicInteger(0);

        VaultTokenLifecycleManager manager = new VaultTokenLifecycleManager(
                () -> status,
                new MetricsCounter(success, skipped, failure)
        );

        manager.renewCycle();

        assertEquals(0, success.get());
        assertEquals(1, skipped.get());
        assertEquals(0, failure.get());
    }

    @Test
    void shouldRecordFailureWhenRenewalThrows() {
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger skipped = new AtomicInteger(0);
        AtomicInteger failure = new AtomicInteger(0);

        VaultTokenLifecycleManager manager = new VaultTokenLifecycleManager(
                () -> {
                    throw new RuntimeException("renew failed");
                },
                new MetricsCounter(success, skipped, failure)
        );

        RuntimeException ex = assertThrows(RuntimeException.class, manager::renewCycle);
        assertEquals("renew failed", ex.getMessage());
        assertEquals(0, success.get());
        assertEquals(0, skipped.get());
        assertEquals(1, failure.get());
    }

    private static final class MetricsCounter implements VaultTokenLifecycleMetrics {
        private final AtomicInteger success;
        private final AtomicInteger skipped;
        private final AtomicInteger failure;

        private MetricsCounter(AtomicInteger success, AtomicInteger skipped, AtomicInteger failure) {
            this.success = success;
            this.skipped = skipped;
            this.failure = failure;
        }

        @Override
        public void recordRenewalSuccess() {
            success.incrementAndGet();
        }

        @Override
        public void recordRenewalSkipped() {
            skipped.incrementAndGet();
        }

        @Override
        public void recordRenewalFailure() {
            failure.incrementAndGet();
        }
    }
}
