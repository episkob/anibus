package it.r2u.anibus.service.export;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.r2u.anibus.model.PortScanResult;

class ScanDiffServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void detectsAddedRemovedAndChangedPorts() throws IOException {
        Path oldXml = tempDir.resolve("old.xml");
        Files.writeString(oldXml, """
                <?xml version=\"1.0\" encoding=\"UTF-8\"?>
                <scan>
                  <meta timestamp=\"2026-05-10T00:00:00\" total=\"2\"/>
                  <results>
                    <port>
                      <number>80</number>
                      <state>Open</state>
                      <service>HTTP</service>
                      <version>nginx/1.0</version>
                      <protocol>TCP</protocol>
                      <latency>10</latency>
                      <banner>old-banner</banner>
                    </port>
                    <port>
                      <number>22</number>
                      <state>Open</state>
                      <service>SSH</service>
                      <version>OpenSSH</version>
                      <protocol>TCP</protocol>
                      <latency>5</latency>
                      <banner>ssh-banner</banner>
                    </port>
                  </results>
                </scan>
                """);

        List<PortScanResult> current = List.of(
                new PortScanResult(80, "HTTP", "new-banner", "TCP", 12, "nginx/1.1", "Open", "Standard"),
                new PortScanResult(443, "HTTPS", "tls-banner", "TCP", 15, "", "Open", "Standard")
        );

        ScanDiffService service = new ScanDiffService();
        ScanDiffService.DiffResult diff = service.diffWithCurrent(oldXml.toFile(), current);

        assertTrue(diff.hasChanges());
        assertEquals(1, diff.addedCount());
        assertEquals(1, diff.removedCount());
        assertEquals(1, diff.changedCount());

        String report = ScanDiffService.formatReport(diff);
        assertTrue(report.contains("ADDED") || report.contains("NEW OPEN PORTS"));
        assertTrue(report.contains("REMOVED") || report.contains("CLOSED PORTS"));
        assertTrue(report.contains("CHANGED") || report.contains("CHANGED SERVICES"));
    }

    @Test
    void returnsNoChangesWhenSnapshotsMatch() throws IOException {
        Path oldXml = tempDir.resolve("same.xml");
        Files.writeString(oldXml, """
                <?xml version=\"1.0\" encoding=\"UTF-8\"?>
                <scan>
                  <meta timestamp=\"2026-05-10T00:00:00\" total=\"1\"/>
                  <results>
                    <port>
                      <number>53</number>
                      <state>open</state>
                      <service>DNS</service>
                      <version></version>
                      <protocol>UDP</protocol>
                      <latency>-1</latency>
                      <banner></banner>
                    </port>
                  </results>
                </scan>
                """);

        List<PortScanResult> current = List.of(
                new PortScanResult(53, "DNS", "", "UDP", -1, "", "open", "UDP")
        );

        ScanDiffService service = new ScanDiffService();
        ScanDiffService.DiffResult diff = service.diffWithCurrent(oldXml.toFile(), current);

        assertFalse(diff.hasChanges());
        assertEquals("Diff: no changes detected between scans.", ScanDiffService.formatReport(diff));
    }

      @Test
      void returnsNoChangesForEmptySnapshots() throws IOException {
        Path oldXml = tempDir.resolve("empty.xml");
        Files.writeString(oldXml, """
            <?xml version=\"1.0\" encoding=\"UTF-8\"?>
            <scan>
              <meta timestamp=\"2026-05-10T00:00:00\" total=\"0\"/>
              <results>
              </results>
            </scan>
            """);

        ScanDiffService service = new ScanDiffService();
        ScanDiffService.DiffResult diff = service.diffWithCurrent(oldXml.toFile(), List.of());

        assertFalse(diff.hasChanges());
        assertEquals(0, diff.addedCount());
        assertEquals(0, diff.removedCount());
        assertEquals(0, diff.changedCount());
      }
}
