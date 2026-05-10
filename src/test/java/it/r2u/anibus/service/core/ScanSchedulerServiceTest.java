package it.r2u.anibus.service.core;

class ScanSchedulerServiceTest {

    private final ScanSchedulerService scheduler = new ScanSchedulerService();

    @org.junit.jupiter.api.Test
    void executesScheduledTaskMultipleTimes() throws InterruptedException {
        try {
            java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(2);
            java.util.concurrent.atomic.AtomicInteger runs = new java.util.concurrent.atomic.AtomicInteger();

            scheduler.schedule(
                    java.time.Duration.ofMillis(100),
                    () -> {
                        runs.incrementAndGet();
                        return java.util.List.of(
                                new it.r2u.anibus.model.PortScanResult(80, "HTTP", "", "TCP", 1, "", "Open", "Scheduled")
                        );
                    },
                    result -> latch.countDown(),
                    err -> org.junit.jupiter.api.Assertions.fail("Unexpected scheduler error: " + err)
            );

            org.junit.jupiter.api.Assertions.assertTrue(latch.await(2, java.util.concurrent.TimeUnit.SECONDS));
            org.junit.jupiter.api.Assertions.assertTrue(runs.get() >= 2);
            org.junit.jupiter.api.Assertions.assertTrue(scheduler.isRunning());
            org.junit.jupiter.api.Assertions.assertNotNull(scheduler.getLastRun());
            org.junit.jupiter.api.Assertions.assertNotNull(scheduler.getNextRun());
            org.junit.jupiter.api.Assertions.assertTrue(scheduler.statusString().contains("active"));
        } finally {
            scheduler.shutdown();
        }
    }

    @org.junit.jupiter.api.Test
    void cancelStopsScheduler() {
        try {
            scheduler.schedule(
                    java.time.Duration.ofMillis(200),
                    java.util.List::of,
                    r -> {
                    },
                    e -> {
                    }
            );

            org.junit.jupiter.api.Assertions.assertTrue(scheduler.isRunning());
            scheduler.cancel();
            org.junit.jupiter.api.Assertions.assertFalse(scheduler.isRunning());
            org.junit.jupiter.api.Assertions.assertTrue(scheduler.statusString().contains("inactive"));
        } finally {
            scheduler.shutdown();
        }
    }
}
