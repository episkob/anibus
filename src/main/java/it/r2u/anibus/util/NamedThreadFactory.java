package it.r2u.anibus.util;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ThreadFactory that assigns human-readable names to threads.
 * <p>
 * Names follow the pattern: {@code <poolName>-<counter>}
 * (e.g. {@code scan-worker-1}, {@code proxy-validator-3}).
 * <p>
 * Usage:
 * <pre>
 *   ExecutorService exec = Executors.newFixedThreadPool(4,
 *       NamedThreadFactory.of("scan-worker"));
 * </pre>
 */
public final class NamedThreadFactory implements ThreadFactory {

    private final String poolName;
    private final boolean daemon;
    private final AtomicInteger counter = new AtomicInteger(1);

    private NamedThreadFactory(String poolName, boolean daemon) {
        this.poolName = poolName;
        this.daemon = daemon;
    }

    /**
     * Creates a daemon {@code NamedThreadFactory} with the given pool name.
     * Daemon threads do not prevent the JVM from exiting.
     */
    public static NamedThreadFactory of(String poolName) {
        return new NamedThreadFactory(poolName, true);
    }

    /**
     * Creates a non-daemon {@code NamedThreadFactory} with the given pool name.
     */
    public static NamedThreadFactory nonDaemon(String poolName) {
        return new NamedThreadFactory(poolName, false);
    }

    @Override
    public Thread newThread(Runnable r) {
        Thread t = new Thread(r, poolName + "-" + counter.getAndIncrement());
        t.setDaemon(daemon);
        return t;
    }
}
