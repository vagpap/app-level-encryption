package dev.wackydevelopers.encryption.blindindex;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class BlindIndexServiceImplTest {

    @Test
    void equalNormalizedPlaintextShouldYieldEqualBlindIndex() {
        CountingKeyProvider provider = new CountingKeyProvider(createFilledKey((byte) 9));
        BlindIndexService service = new BlindIndexServiceImpl(provider);

        String a = service.computeBlindIndex("  Secret   Value  ");
        String b = service.computeBlindIndex("secret value");

        assertEquals(a, b);
    }

    @Test
    void blindIndexShouldBeTruncatedTo128BitsHex() {
        CountingKeyProvider provider = new CountingKeyProvider(createFilledKey((byte) 2));
        BlindIndexService service = new BlindIndexServiceImpl(provider);

        String index = service.computeBlindIndex("hello");

        assertEquals(32, index.length());
        assertTrue(index.matches("^[0-9a-f]{32}$"));
    }

    @Test
    void bikShouldLoadOnceAndUseInProcessCache() {
        CountingKeyProvider provider = new CountingKeyProvider(createFilledKey((byte) 7));
        BlindIndexService service = new BlindIndexServiceImpl(provider);

        service.initialize();
        service.computeBlindIndex("value-1");
        service.computeBlindIndex("value-2");

        assertEquals(1, provider.loadCount.get());
    }

    @Test
    void exactMatchQueryShouldRejectUnsupportedWildcardPatterns() {
        CountingKeyProvider provider = new CountingKeyProvider(createFilledKey((byte) 4));
        BlindIndexService service = new BlindIndexServiceImpl(provider);

        assertThrows(UnsupportedBlindIndexQueryException.class,
                () -> service.computeBlindIndexForExactMatchQuery("foo%"));
        assertThrows(UnsupportedBlindIndexQueryException.class,
                () -> service.computeBlindIndexForExactMatchQuery("foo*"));
        assertThrows(UnsupportedBlindIndexQueryException.class,
                () -> service.computeBlindIndexForExactMatchQuery("foo?"));
    }

    @Test
    void exactMatchQueryShouldProduceSameOutputAsDirectCompute() {
        CountingKeyProvider provider = new CountingKeyProvider(createFilledKey((byte) 5));
        BlindIndexService service = new BlindIndexServiceImpl(provider);

        String a = service.computeBlindIndex("Exact Value");
        String b = service.computeBlindIndexForExactMatchQuery("exact value");

        assertEquals(a, b);
    }

    private static byte[] createFilledKey(byte value) {
        byte[] key = new byte[32];
        Arrays.fill(key, value);
        return key;
    }

    private static final class CountingKeyProvider implements BlindIndexKeyProvider {
        private final byte[] key;
        private final AtomicInteger loadCount = new AtomicInteger(0);

        private CountingKeyProvider(byte[] key) {
            this.key = key;
        }

        @Override
        public byte[] loadBlindIndexKey() {
            loadCount.incrementAndGet();
            return Arrays.copyOf(key, key.length);
        }
    }
}
