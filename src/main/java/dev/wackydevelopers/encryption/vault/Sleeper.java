package dev.wackydevelopers.encryption.vault;

@FunctionalInterface
public interface Sleeper {
    void sleep(long millis) throws InterruptedException;
}
