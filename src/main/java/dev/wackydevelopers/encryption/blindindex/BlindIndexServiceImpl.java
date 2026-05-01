package dev.wackydevelopers.encryption.blindindex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class BlindIndexServiceImpl implements RotatableBlindIndexService {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int TRUNCATED_BYTES = 16;

    private final BlindIndexKeyProvider keyProvider;

    private final AtomicReference<byte[]> cachedBik = new AtomicReference<>();

    public BlindIndexServiceImpl(BlindIndexKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public void initialize() {
        ensureBikLoaded();
    }

    @Override
    public String computeBlindIndex(String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        String normalized = normalize(plaintext);
        return computeHmacTruncatedHex(normalized, ensureBikLoaded());
    }

    @Override
    public String computeBlindIndexForExactMatchQuery(String query) {
        Objects.requireNonNull(query, "query must not be null");
        validateExactMatchQuery(query);
        return computeBlindIndex(query);
    }

    private void validateExactMatchQuery(String query) {
        if (query.isBlank()) {
            throw new UnsupportedBlindIndexQueryException("Blank query is not supported");
        }

        if (query.contains("%") || query.contains("*") || query.contains("?") || query.contains("_")) {
            throw new UnsupportedBlindIndexQueryException("Wildcard query patterns are not supported");
        }
    }

    protected String computeHmacTruncatedHex(String normalizedInput, byte[] bik) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(bik, HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(normalizedInput.getBytes(StandardCharsets.UTF_8));
            byte[] truncated = Arrays.copyOf(digest, TRUNCATED_BYTES);
            return toHex(truncated);
        } catch (Exception ex) {
            throw new BlindIndexException("Blind index computation failed", ex);
        }
    }

    private byte[] ensureBikLoaded() {
        byte[] bik = cachedBik.get();
        if (bik != null) {
            return bik;
        }

        synchronized (this) {
            byte[] current = cachedBik.get();
            if (current == null) {
                byte[] loaded = Objects.requireNonNull(keyProvider.loadBlindIndexKey(), "BIK must not be null");
                if (loaded.length == 0) {
                    throw new BlindIndexException("BIK must not be empty");
                }
                cachedBik.set(Arrays.copyOf(loaded, loaded.length));
            }
            return cachedBik.get();
        }
    }

    protected String normalize(String input) {
        String trimmed = input.trim();
        String collapsedWhitespace = trimmed.replaceAll("\\s+", " ");
        String lowerCased = collapsedWhitespace.toLowerCase(Locale.ROOT);
        return Normalizer.normalize(lowerCased, Normalizer.Form.NFC);
    }

    private String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    @Override
    public void rotateKey(byte[] newBik) {
        Objects.requireNonNull(newBik, "newBik must not be null");
        if (newBik.length == 0) {
            throw new BlindIndexException("newBik must not be empty");
        }
        cachedBik.set(Arrays.copyOf(newBik, newBik.length));
    }

    public String computeBlindIndexWithKey(String plaintext, byte[] bik) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        Objects.requireNonNull(bik, "bik must not be null");
        String normalized = normalize(plaintext);
        return computeHmacTruncatedHex(normalized, bik);
    }
}
