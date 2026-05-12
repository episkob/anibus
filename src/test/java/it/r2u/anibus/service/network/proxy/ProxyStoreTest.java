package it.r2u.anibus.service.network.proxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void savesAndLoadsProxySetRoundTrip() {
        Path path = tempDir.resolve("proxy-pool.json");
        ProxyStore store = new ProxyStore(path);

        Set<ProxyNode> source = Set.of(
                new ProxyNode("1.2.3.4", 8080, ProxyType.HTTP, "DE", 100),
                new ProxyNode("5.6.7.8", 1080, ProxyType.SOCKS5, "FR", 50));

        assertFalse(store.exists());
        store.save(source);
        assertTrue(store.exists());

        Set<ProxyNode> loaded = store.load();
        assertEquals(source, loaded);
    }

    @Test
    void skipsMalformedLinesAndStillLoadsValidEntries() throws IOException {
        Path path = tempDir.resolve("proxy-pool.json");
        Files.writeString(path, """
            {"host":"1.1.1.1","port":8080,"type":"HTTP","country":"DE","latency":123}
            not-json
            {"host":"2.2.2.2","port":-1,"type":"HTTP","country":"FR","latency":10}
            {"host":"3.3.3.3","port":3128,"type":"SOCKS5","country":"IT","latency":80}
            """, StandardCharsets.UTF_8);

        ProxyStore store = new ProxyStore(path);
        Set<ProxyNode> loaded = store.load();

        assertEquals(2, loaded.size());
        assertTrue(loaded.contains(new ProxyNode("1.1.1.1", 8080, ProxyType.HTTP, "DE", 123)));
        assertTrue(loaded.contains(new ProxyNode("3.3.3.3", 3128, ProxyType.SOCKS5, "IT", 80)));
    }
}
