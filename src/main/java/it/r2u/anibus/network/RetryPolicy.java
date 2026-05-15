package it.r2u.anibus.network;

import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Exponential backoff retry policy with jitter for transient network operations.
 *
 * <p>Retries only on {@link IOException}. Other exceptions propagate immediately.
 * Delay between attempts grows exponentially up to {@code maxDelayMs}, with a
 * random jitter of ±{@code jitterFactor} to avoid thundering-herd effects.
 *
 * <pre>{@code
 * String body = RetryPolicy.DEFAULT.execute(() -> fetchSpec(url));
 * }</pre>
 */
public final class RetryPolicy {

    /**
     * Default policy: 3 attempts, 200 ms base delay, ×2 multiplier,
     * 5 s cap, ±20 % jitter.
     */
    public static final RetryPolicy DEFAULT = new RetryPolicy(3, 200, 2.0, 5_000, 0.2);

    private final int maxAttempts;
    private final long initialDelayMs;
    private final double multiplier;
    private final long maxDelayMs;
    private final double jitterFactor;

    /**
     * @param maxAttempts    total number of attempts (≥ 1)
     * @param initialDelayMs delay before the 2nd attempt in milliseconds (≥ 0)
     * @param multiplier     delay growth factor per retry (≥ 1.0)
     * @param maxDelayMs     upper cap for computed delay in milliseconds (≥ 0)
     * @param jitterFactor   fraction of base delay added/subtracted randomly, in [0, 1]
     */
    public RetryPolicy(int maxAttempts, long initialDelayMs, double multiplier,
                       long maxDelayMs, double jitterFactor) {
        if (maxAttempts < 1)
            throw new IllegalArgumentException("maxAttempts must be >= 1, got: " + maxAttempts);
        if (initialDelayMs < 0)
            throw new IllegalArgumentException("initialDelayMs must be >= 0, got: " + initialDelayMs);
        if (multiplier < 1.0)
            throw new IllegalArgumentException("multiplier must be >= 1.0, got: " + multiplier);
        if (maxDelayMs < 0)
            throw new IllegalArgumentException("maxDelayMs must be >= 0, got: " + maxDelayMs);
        if (jitterFactor < 0 || jitterFactor > 1)
            throw new IllegalArgumentException("jitterFactor must be in [0, 1], got: " + jitterFactor);

        this.maxAttempts = maxAttempts;
        this.initialDelayMs = initialDelayMs;
        this.multiplier = multiplier;
        this.maxDelayMs = maxDelayMs;
        this.jitterFactor = jitterFactor;
    }

    /** Action that may throw {@link IOException}. */
    @FunctionalInterface
    public interface IOCallable<T> {
        T call() throws IOException;
    }

    /**
     * Executes {@code action} retrying up to {@link #maxAttempts} times on {@link IOException}.
     *
     * @param action the network operation to execute
     * @param <T>    return type
     * @return result of the first successful invocation
     * @throws IOException          if every attempt throws {@code IOException}
     * @throws InterruptedException if the calling thread is interrupted while sleeping between retries
     */
    public <T> T execute(IOCallable<T> action) throws IOException, InterruptedException {
        for (int attempt = 0; ; attempt++) {
            try {
                return action.call();
            } catch (IOException ex) {
                if (attempt >= maxAttempts - 1) throw ex;
                sleepBeforeRetry(attempt);
            }
        }
    }

    private void sleepBeforeRetry(int attempt) throws InterruptedException {
        Thread.sleep(delayMs(attempt));
    }

    /**
     * Computes the sleep duration before the {@code (attemptIndex + 1)}-th retry.
     * {@code attemptIndex} is 0-based (0 = before 2nd attempt, 1 = before 3rd, …).
     *
     * <pre>delay = min(initialDelay × multiplier^attemptIndex, maxDelay) × (1 ± jitter)</pre>
     */
    public long delayMs(int attemptIndex) {
        double base = initialDelayMs * Math.pow(multiplier, attemptIndex);
        double capped = Math.min(base, maxDelayMs);
        double jitter = (ThreadLocalRandom.current().nextDouble() * 2.0 - 1.0) * jitterFactor;
        return Math.max(0L, (long) (capped * (1.0 + jitter)));
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public int maxAttempts() { return maxAttempts; }
    public long initialDelayMs() { return initialDelayMs; }
    public double multiplier() { return multiplier; }
    public long maxDelayMs() { return maxDelayMs; }
    public double jitterFactor() { return jitterFactor; }
}
