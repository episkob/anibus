package it.r2u.anibus.service.network;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import it.r2u.anibus.network.RetryPolicy;

@SuppressWarnings("ThrowableResultOfMethodCallIgnored")
class RetryPolicyTest {

    @Test
    void successOnFirstAttemptReturnsImmediately() throws Exception {
        RetryPolicy policy = new RetryPolicy(3, 0, 2.0, 0, 0);
        String result = policy.execute(() -> "ok");
        assertEquals("ok", result);
    }

    @Test
    void retriesOnIoExceptionAndSucceedsOnThirdAttempt() throws Exception {
        RetryPolicy policy = new RetryPolicy(3, 0, 2.0, 0, 0);
        AtomicInteger calls = new AtomicInteger();

        String result = policy.execute(() -> {
            if (calls.incrementAndGet() < 3) throw new IOException("transient");
            return "recovered";
        });

        assertEquals("recovered", result);
        assertEquals(3, calls.get());
    }

    @Test
    void throwsLastExceptionWhenAllAttemptsFail() {
        RetryPolicy policy = new RetryPolicy(2, 0, 2.0, 0, 0);
        AtomicInteger calls = new AtomicInteger();

        IOException ex = assertThrows(IOException.class, () -> policy.execute(() -> {
            calls.incrementAndGet();
            throw new IOException("fail");
        }));

        assertEquals("fail", ex.getMessage());
        assertEquals(2, calls.get());
    }

    @Test
    void singleAttemptPolicyNeverRetries() {
        RetryPolicy policy = new RetryPolicy(1, 0, 1.0, 0, 0);
        AtomicInteger calls = new AtomicInteger();

        assertThrows(IOException.class, () -> policy.execute(() -> {
            calls.incrementAndGet();
            throw new IOException("only attempt");
        }));

        assertEquals(1, calls.get());
    }

    @Test
    void delayGrowsExponentiallyWithinJitterBounds() {
        RetryPolicy policy = new RetryPolicy(5, 100, 2.0, 10_000, 0.2);

        // attempt 0 → base = 100 ms → jitter range [80, 120]
        for (int i = 0; i < 50; i++) {
            long d = policy.delayMs(0);
            assertTrue(d >= 80 && d <= 120, "delay(0) out of [80,120]: " + d);
        }

        // attempt 1 → base = 200 ms → jitter range [160, 240]
        for (int i = 0; i < 50; i++) {
            long d = policy.delayMs(1);
            assertTrue(d >= 160 && d <= 240, "delay(1) out of [160,240]: " + d);
        }
    }

    @Test
    void delayCapIsRespected() {
        RetryPolicy policy = new RetryPolicy(10, 1_000, 3.0, 500, 0);
        // base at attempt 2 = 1000 × 3^2 = 9000 → capped at 500, no jitter
        assertEquals(500, policy.delayMs(2));
    }

    @Test
    void zeroJitterProducesExactDelay() {
        RetryPolicy policy = new RetryPolicy(5, 100, 2.0, 10_000, 0);
        assertEquals(100, policy.delayMs(0));
        assertEquals(200, policy.delayMs(1));
        assertEquals(400, policy.delayMs(2));
    }

    @Test
    void constructorValidatesParameters() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(0, 100, 2.0, 1000, 0.1));   // maxAttempts < 1
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, -1, 2.0, 1000, 0.1));    // initialDelay < 0
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100, 0.5, 1000, 0.1));   // multiplier < 1
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100, 2.0, -1, 0.1));     // maxDelay < 0
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100, 2.0, 1000, 1.5));   // jitter > 1
    }

    @Test
    void defaultPolicyHasExpectedParameters() {
        RetryPolicy p = RetryPolicy.DEFAULT;
        assertEquals(3,    p.maxAttempts());
        assertEquals(200L, p.initialDelayMs());
        assertEquals(2.0,  p.multiplier());
        assertEquals(5_000L, p.maxDelayMs());
        assertEquals(0.2,  p.jitterFactor());
    }
}
