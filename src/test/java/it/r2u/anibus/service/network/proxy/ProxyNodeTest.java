package it.r2u.anibus.service.network.proxy;

import java.net.InetSocketAddress;
import java.net.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ProxyNodeTest {

    @Test
    void convertsToJavaProxyAndSupportsCopyHelpers() {
        ProxyNode node = new ProxyNode("127.0.0.1", 9050, ProxyType.SOCKS5, "XX", 70);

        Proxy javaProxy = node.toJavaProxy();
        assertEquals(Proxy.Type.SOCKS, javaProxy.type());

        InetSocketAddress address = (InetSocketAddress) javaProxy.address();
        assertEquals("127.0.0.1", address.getHostString());
        assertEquals(9050, address.getPort());

        ProxyNode withLatency = node.withLatency(12);
        ProxyNode withCountry = node.withCountry("DE");

        assertEquals(12, withLatency.latencyMs());
        assertEquals("DE", withCountry.countryCode());
        assertEquals("XX", node.countryCode());
        assertEquals(70, node.latencyMs());
    }

    @Test
    void marksAliveStateAndFormatsText() {
        ProxyNode alive = new ProxyNode("1.1.1.1", 8080, ProxyType.HTTP, "FR", 0);
        ProxyNode dead = new ProxyNode("1.1.1.2", 8080, ProxyType.HTTP, "FR", -1);

        assertTrue(alive.isAlive());
        assertFalse(dead.isAlive());
        assertTrue(alive.toString().contains("1.1.1.1:8080"));
        assertTrue(alive.toString().contains("latency=0ms"));
    }
}
