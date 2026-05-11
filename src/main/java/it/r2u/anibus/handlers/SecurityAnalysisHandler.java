package it.r2u.anibus.handlers;

import it.r2u.anibus.model.LeakInfo;
import it.r2u.anibus.service.analysis.*;
import it.r2u.anibus.service.network.*;
import it.r2u.anibus.ui.ConsoleViewManager;

import javafx.concurrent.Task;
import javafx.scene.control.ProgressBar;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Handles all security analysis scan operations extracted from AnibusController.
 * Each run*() method orchestrates one security check:
 * validate target → start daemon Task → report result to console.
 */
public class SecurityAnalysisHandler {

    private final Supplier<String>  targetUrlSupplier;
    private final Supplier<String>  targetHostSupplier;
    private final Supplier<String>  consoleTextSupplier;
    private final Supplier<Integer> firstScanPortSupplier;
    private final Supplier<Integer> tlsPortSupplier;
    private final ConsoleViewManager console;
    private final ProgressBar        progressBar;
    private final Consumer<String>   setStatus;

    private final XssDetector               xssDetector;
    private final CorsChecker               corsChecker;
    private final JwtAnalyzer               jwtAnalyzer;
    private final SsrfDetector              ssrfDetector;
    private final DirectoryBruteforcer      dirBruteforcer;
    private final WhoisService              whoisService;
    private final SslTlsAuditor             sslTlsAuditor;
    private final GraphqlScanner            graphqlScanner;
    private final XxeDetector              xxeDetector;
    private final SubdomainTakeoverChecker  takeoverChecker;
    private final DnsZoneTransferService    dnsAxfrService;
    private final Log4ShellChecker          log4ShellChecker;
    private final Spring4ShellChecker       spring4ShellChecker;
    private final WebSocketDetector         webSocketDetector;
    private final HttpProtocolDetector      httpProtocolDetector;
    private final AsnLookupService          asnLookupService;
    private final HeartbleedChecker         heartbleedChecker;
    private final ApiSecurityModeService    apiSecurityModeService;
    private final PassiveReconService       passiveReconService;
    private final SecretsValidationService  secretsValidationService;
    private final Supplier<List<LeakInfo>>  leaksSupplier;

    private SecurityAnalysisHandler(Builder b) {
        this.targetUrlSupplier     = b.targetUrlSupplier;
        this.targetHostSupplier    = b.targetHostSupplier;
        this.consoleTextSupplier   = b.consoleTextSupplier;
        this.firstScanPortSupplier = b.firstScanPortSupplier;
        this.tlsPortSupplier       = b.tlsPortSupplier;
        this.console               = b.console;
        this.progressBar           = b.progressBar;
        this.setStatus             = b.setStatus;
        this.xssDetector           = b.xssDetector;
        this.corsChecker           = b.corsChecker;
        this.jwtAnalyzer           = b.jwtAnalyzer;
        this.ssrfDetector          = b.ssrfDetector;
        this.dirBruteforcer        = b.dirBruteforcer;
        this.whoisService          = b.whoisService;
        this.sslTlsAuditor         = b.sslTlsAuditor;
        this.graphqlScanner        = b.graphqlScanner;
        this.xxeDetector           = b.xxeDetector;
        this.takeoverChecker       = b.takeoverChecker;
        this.dnsAxfrService        = b.dnsAxfrService;
        this.log4ShellChecker      = b.log4ShellChecker;
        this.spring4ShellChecker   = b.spring4ShellChecker;
        this.webSocketDetector     = b.webSocketDetector;
        this.httpProtocolDetector  = b.httpProtocolDetector;
        this.asnLookupService      = b.asnLookupService;
        this.heartbleedChecker     = b.heartbleedChecker;
        this.apiSecurityModeService   = b.apiSecurityModeService;
        this.passiveReconService      = b.passiveReconService;
        this.secretsValidationService = b.secretsValidationService;
        this.leaksSupplier         = b.leaksSupplier;
    }

    // ── Public scan methods ──────────────────────────────────────────────────

    public void runXssScan() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL for XSS scan"); return; }
        Task<List<XssDetector.XssResult>> task = new Task<>() {
            @Override protected List<XssDetector.XssResult> call() {
                return xssDetector.scan(target, null, p -> updateProgress(p, 1.0));
            }
        };
        bindProgress(task);
        setStatus.accept("XSS scan running on " + target + "...");
        task.setOnSucceeded(ev -> {
            unbindProgress();
            List<XssDetector.XssResult> hits = task.getValue();
            console.appendRawText("\n" + XssDetector.formatReport(hits, target) + "\n");
            long vulns = hits.stream().filter(XssDetector.XssResult::reflected).count();
            setStatus.accept("XSS scan completed: " + vulns + " reflected finding(s)");
        });
        task.setOnFailed(ev -> { unbindProgress(); setStatus.accept("XSS scan failed: " + msg(task)); });
        daemon(task, "xss-scan");
    }

    public void runCorsCheck() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL for CORS check"); return; }
        Task<List<CorsChecker.CorsResult>> task = new Task<>() {
            @Override protected List<CorsChecker.CorsResult> call() { return corsChecker.check(target); }
        };
        setStatus.accept("CORS check running on " + target + "...");
        task.setOnSucceeded(ev -> {
            List<CorsChecker.CorsResult> r = task.getValue();
            console.appendRawText("\n" + CorsChecker.formatReport(r, target) + "\n");
            long issues = r.stream().filter(c -> c.risk() != CorsChecker.CorsRisk.SAFE).count();
            setStatus.accept("CORS check completed: " + issues + " misconfiguration(s)");
        });
        task.setOnFailed(ev -> setStatus.accept("CORS check failed: " + msg(task)));
        daemon(task, "cors-check");
    }

    public void runJwtAnalysis() {
        String rawText = consoleTextSupplier.get();
        if (rawText == null || rawText.isBlank()) {
            setStatus.accept("Run JS Analysis first to populate console with JWT tokens");
            return;
        }
        List<JwtAnalyzer.JwtFinding> findings = jwtAnalyzer.analyzeFromText(rawText);
        console.appendRawText("\n" + JwtAnalyzer.formatReport(findings, targetHostSupplier.get()) + "\n");
        setStatus.accept("JWT analysis completed: " + findings.size() + " token(s) found");
    }

    public void runSsrfScan() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<List<SsrfDetector.SsrfResult>> task = new Task<>() {
            @Override protected List<SsrfDetector.SsrfResult> call() {
                return ssrfDetector.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        bindProgress(task);
        setStatus.accept("Running SSRF scan against " + target + "\u2026");
        task.setOnSucceeded(ev -> {
            unbindProgress();
            List<SsrfDetector.SsrfResult> r = task.getValue();
            console.appendRawText("\n" + SsrfDetector.formatReport(r, target) + "\n");
            long vulns = r.stream().filter(SsrfDetector.SsrfResult::potentiallyVulnerable).count();
            setStatus.accept("SSRF scan complete: " + vulns + " potential issue(s) found");
        });
        task.setOnFailed(ev -> { unbindProgress(); setStatus.accept("SSRF scan error: " + msg(task)); });
        daemon(task, "ssrf-scan");
    }

    public void runDirectoryBruteforce() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<List<DirectoryBruteforcer.PathResult>> task = new Task<>() {
            @Override protected List<DirectoryBruteforcer.PathResult> call() {
                return dirBruteforcer.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        bindProgress(task);
        setStatus.accept("Directory bruteforce running against " + target + "\u2026");
        task.setOnSucceeded(ev -> {
            unbindProgress();
            List<DirectoryBruteforcer.PathResult> hits = task.getValue();
            console.appendRawText("\n" + DirectoryBruteforcer.formatReport(hits, target) + "\n");
            setStatus.accept("Directory bruteforce complete: " + hits.size() + " path(s) found");
        });
        task.setOnFailed(ev -> { unbindProgress(); setStatus.accept("Dir bruteforce error: " + msg(task)); });
        daemon(task, "dir-bruteforce");
    }

    public void runWhoisLookup() {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target host/domain first"); return; }
        Task<WhoisService.WhoisResult> task = new Task<>() {
            @Override protected WhoisService.WhoisResult call() { return whoisService.lookup(host); }
        };
        setStatus.accept("WHOIS lookup for " + host + "\u2026");
        task.setOnSucceeded(ev -> {
            console.appendRawText("\n" + WhoisService.formatReport(task.getValue()) + "\n");
            setStatus.accept("WHOIS lookup complete for " + host);
        });
        task.setOnFailed(ev -> setStatus.accept("WHOIS error: " + msg(task)));
        daemon(task, "whois-lookup");
    }

    public void runSslAudit() {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target host first"); return; }
        Task<SslTlsAuditor.AuditResult> task = new Task<>() {
            @Override protected SslTlsAuditor.AuditResult call() { return sslTlsAuditor.audit(host, 443); }
        };
        setStatus.accept("SSL/TLS audit running for " + host + "\u2026");
        task.setOnSucceeded(ev -> {
            SslTlsAuditor.AuditResult r = task.getValue();
            console.appendRawText("\n" + SslTlsAuditor.formatReport(r) + "\n");
            setStatus.accept("SSL/TLS audit complete [" + r.overallRisk() + "]");
        });
        task.setOnFailed(ev -> setStatus.accept("SSL audit error: " + msg(task)));
        daemon(task, "ssl-audit");
    }

    public void runGraphqlScan() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<List<GraphqlScanner.GraphqlEndpoint>> task = new Task<>() {
            @Override protected List<GraphqlScanner.GraphqlEndpoint> call() {
                return graphqlScanner.scan(target);
            }
        };
        setStatus.accept("GraphQL introspection scan running against " + target + "\u2026");
        task.setOnSucceeded(ev -> {
            List<GraphqlScanner.GraphqlEndpoint> eps = task.getValue();
            console.appendRawText("\n" + GraphqlScanner.formatReport(eps, target) + "\n");
            long exposed = eps.stream().filter(GraphqlScanner.GraphqlEndpoint::introspectionEnabled).count();
            setStatus.accept("GraphQL scan complete: " + exposed + " exposed endpoint(s) of " + eps.size() + " found");
        });
        task.setOnFailed(ev -> setStatus.accept("GraphQL scan error: " + msg(task)));
        daemon(task, "graphql-scan");
    }

    public void runXxeScan() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<List<XxeDetector.XxeResult>> task = new Task<>() {
            @Override protected List<XxeDetector.XxeResult> call() {
                return xxeDetector.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        bindProgress(task);
        setStatus.accept("XXE scan running against " + target + "\u2026");
        task.setOnSucceeded(ev -> {
            unbindProgress();
            List<XxeDetector.XxeResult> r = task.getValue();
            console.appendRawText("\n" + XxeDetector.formatReport(r, target) + "\n");
            setStatus.accept("XXE scan complete: " + r.size() + " finding(s)");
        });
        task.setOnFailed(ev -> { unbindProgress(); setStatus.accept("XXE scan error: " + msg(task)); });
        daemon(task, "xxe-scan");
    }

    public void runTakeoverCheck() {
        String domain = targetHostSupplier.get();
        if (domain.isBlank()) { setStatus.accept("Enter a domain first"); return; }
        Task<List<SubdomainTakeoverChecker.TakeoverFinding>> task = new Task<>() {
            @Override protected List<SubdomainTakeoverChecker.TakeoverFinding> call() {
                return takeoverChecker.check(domain);
            }
        };
        setStatus.accept("Subdomain takeover check running for " + domain + "\u2026");
        task.setOnSucceeded(ev -> {
            List<SubdomainTakeoverChecker.TakeoverFinding> found = task.getValue();
            console.appendRawText("\n" + SubdomainTakeoverChecker.formatReport(found, domain) + "\n");
            long vuln = found.stream().filter(SubdomainTakeoverChecker.TakeoverFinding::vulnerable).count();
            setStatus.accept("Takeover check complete: " + vuln + " vulnerable of " + found.size() + " probed");
        });
        task.setOnFailed(ev -> setStatus.accept("Takeover check error: " + msg(task)));
        daemon(task, "takeover-check");
    }

    public void runDnsAxfr() {
        String domain = targetHostSupplier.get();
        if (domain.isBlank()) { setStatus.accept("Enter a domain first"); return; }
        Task<DnsZoneTransferService.ZoneTransferResult> task = new Task<>() {
            @Override protected DnsZoneTransferService.ZoneTransferResult call() {
                return dnsAxfrService.attemptAxfr(domain);
            }
        };
        setStatus.accept("DNS Zone Transfer (AXFR) attempt for " + domain + "\u2026");
        task.setOnSucceeded(ev -> {
            DnsZoneTransferService.ZoneTransferResult r = task.getValue();
            console.appendRawText("\n" + DnsZoneTransferService.formatReport(r) + "\n");
            setStatus.accept("DNS AXFR: " + (r.transferSucceeded()
                ? "SUCCEEDED \u2014 " + r.records().size() + " record(s) retrieved!"
                : "refused (zone transfer is protected)"));
        });
        task.setOnFailed(ev -> setStatus.accept("AXFR error: " + msg(task)));
        daemon(task, "dns-axfr");
    }

    public void runLog4ShellCheck(int defaultPort) {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target first"); return; }
        int port = firstScanPortSupplier.get() > 0 ? firstScanPortSupplier.get() : defaultPort;
        Task<List<Log4ShellChecker.Log4ShellFinding>> task = new Task<>() {
            @Override protected List<Log4ShellChecker.Log4ShellFinding> call() {
                return log4ShellChecker.scan(host, port);
            }
        };
        setStatus.accept("Log4Shell check (CVE-2021-44228) against " + host + ":" + port + "\u2026");
        task.setOnSucceeded(ev -> {
            List<Log4ShellChecker.Log4ShellFinding> found = task.getValue();
            console.appendRawText("\n" + Log4ShellChecker.formatReport(found, host) + "\n");
            setStatus.accept("Log4Shell check complete: " + found.size() + " indicator(s) found");
        });
        task.setOnFailed(ev -> setStatus.accept("Log4Shell check error: " + msg(task)));
        daemon(task, "log4shell-check");
    }

    public void runSpring4ShellCheck() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<List<Spring4ShellChecker.Spring4ShellFinding>> task = new Task<>() {
            @Override protected List<Spring4ShellChecker.Spring4ShellFinding> call() {
                return spring4ShellChecker.scan(target);
            }
        };
        setStatus.accept("Spring4Shell check (CVE-2022-22965) against " + target + "\u2026");
        task.setOnSucceeded(ev -> {
            List<Spring4ShellChecker.Spring4ShellFinding> found = task.getValue();
            console.appendRawText("\n" + Spring4ShellChecker.formatReport(found, target) + "\n");
            setStatus.accept("Spring4Shell check complete: " + found.size() + " indicator(s) found");
        });
        task.setOnFailed(ev -> setStatus.accept("Spring4Shell error: " + msg(task)));
        daemon(task, "spring4shell-check");
    }

    public void runWebSocketDetect(int defaultPort) {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target first"); return; }
        int port = firstScanPortSupplier.get() > 0 ? firstScanPortSupplier.get() : defaultPort;
        Task<List<WebSocketDetector.WsEndpoint>> task = new Task<>() {
            @Override protected List<WebSocketDetector.WsEndpoint> call() {
                return webSocketDetector.detect(host, port);
            }
        };
        setStatus.accept("WebSocket detection on " + host + ":" + port + "\u2026");
        task.setOnSucceeded(ev -> {
            List<WebSocketDetector.WsEndpoint> eps = task.getValue();
            console.appendRawText("\n" + WebSocketDetector.formatReport(eps, host + ":" + port) + "\n");
            setStatus.accept("WebSocket detection complete: " + eps.size() + " endpoint(s) found");
        });
        task.setOnFailed(ev -> setStatus.accept("WebSocket detect error: " + msg(task)));
        daemon(task, "ws-detect");
    }

    public void runHttpProtocolDetect(int defaultPort) {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target first"); return; }
        int port = firstScanPortSupplier.get() > 0 ? firstScanPortSupplier.get() : defaultPort;
        Task<HttpProtocolDetector.ProtocolResult> task = new Task<>() {
            @Override protected HttpProtocolDetector.ProtocolResult call() {
                return httpProtocolDetector.detect(host, port);
            }
        };
        setStatus.accept("HTTP protocol detection on " + host + ":" + port + "\u2026");
        task.setOnSucceeded(ev -> {
            HttpProtocolDetector.ProtocolResult r = task.getValue();
            console.appendRawText("\n" + HttpProtocolDetector.formatReport(r) + "\n");
            setStatus.accept(String.format("HTTP proto: HTTP/1.1=%s  HTTP/2=%s  HTTP/3=%s",
                r.http11() ? "\u2713" : "\u2717",
                r.http2() ? "\u2713" : "\u2717",
                r.http3Advertised() ? "\u2713" : "\u2717"));
        });
        task.setOnFailed(ev -> setStatus.accept("HTTP protocol detect error: " + msg(task)));
        daemon(task, "http-proto-detect");
    }

    public void runAsnLookup() {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target IP or host first"); return; }
        Task<AsnLookupService.AsnInfo> task = new Task<>() {
            @Override protected AsnLookupService.AsnInfo call() {
                String ip = host;
                try { ip = java.net.InetAddress.getByName(host).getHostAddress(); }
                catch (java.net.UnknownHostException | SecurityException ignored) {}
                return asnLookupService.lookup(ip);
            }
        };
        setStatus.accept("ASN lookup for " + host + "\u2026");
        task.setOnSucceeded(ev -> {
            AsnLookupService.AsnInfo info = task.getValue();
            console.appendRawText("\n" + AsnLookupService.formatReport(info) + "\n");
            String asn = info.asn() != null ? "AS" + info.asn() : "unknown";
            setStatus.accept("ASN lookup done: " + asn + (info.asnName() != null ? " \u2014 " + info.asnName() : ""));
        });
        task.setOnFailed(ev -> setStatus.accept("ASN lookup error: " + msg(task)));
        daemon(task, "asn-lookup");
    }

    public void runHeartbleedCheck() {
        String host = targetHostSupplier.get();
        if (host.isBlank()) { setStatus.accept("Enter a target first"); return; }
        int port = tlsPortSupplier.get();
        Task<HeartbleedChecker.HeartbleedResult> task = new Task<>() {
            @Override protected HeartbleedChecker.HeartbleedResult call() {
                return heartbleedChecker.check(host, port);
            }
        };
        setStatus.accept("Heartbleed check on " + host + ":" + port + "\u2026");
        task.setOnSucceeded(ev -> {
            HeartbleedChecker.HeartbleedResult r = task.getValue();
            console.appendRawText("\n" + HeartbleedChecker.formatReport(r) + "\n");
            setStatus.accept(r.vulnerable()
                ? "\u26a0 VULNERABLE to Heartbleed! CVE-2014-0160"
                : "Heartbleed check done \u2014 not vulnerable");
        });
        task.setOnFailed(ev -> setStatus.accept("Heartbleed check error: " + msg(task)));
        daemon(task, "heartbleed-check");
    }

    public void runApiSecurityMode() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL first"); return; }
        Task<ApiSecurityModeService.ScanResult> task = new Task<>() {
            @Override protected ApiSecurityModeService.ScanResult call() {
                return apiSecurityModeService.scan(target);
            }
        };
        setStatus.accept("API Security Mode running against " + target + "...");
        task.setOnSucceeded(ev -> {
            ApiSecurityModeService.ScanResult r = task.getValue();
            console.appendRawText("\n" + ApiSecurityModeService.formatReport(r) + "\n");
            setStatus.accept("API Security Mode complete: " + r.probes().size() + " endpoint probe(s)");
        });
        task.setOnFailed(ev -> setStatus.accept("API Security Mode failed: " + msg(task)));
        daemon(task, "api-security-mode");
    }

    public void runPassiveRecon() {
        String target = targetUrlSupplier.get();
        if (target.isBlank()) { setStatus.accept("Enter a target URL for passive recon"); return; }
        Task<PassiveReconService.PassiveReconResult> task = new Task<>() {
            @Override protected PassiveReconService.PassiveReconResult call() {
                return passiveReconService.scan(target);
            }
        };
        setStatus.accept("Passive recon running on " + target + "...");
        progressBar.setVisible(true);
        task.setOnSucceeded(ev -> {
            progressBar.setVisible(false);
            console.appendRawText("\n" + PassiveReconService.formatReport(task.getValue()) + "\n");
            setStatus.accept("Passive recon completed for " + target);
        });
        task.setOnFailed(ev -> {
            progressBar.setVisible(false);
            setStatus.accept("Passive recon failed: " + msg(task));
        });
        daemon(task, "passive-recon");
    }

    public void runSecretsValidation() {
        List<LeakInfo> leaks = leaksSupplier.get();
        if (leaks == null || leaks.isEmpty()) {
            setStatus.accept("No JS analysis results available. Run JS Security Scan first.");
            return;
        }
        String host = targetHostSupplier.get();
        String source = host.isBlank() ? "JS Analysis" : host;
        Task<List<SecretsValidationService.ValidationResult>> task = new Task<>() {
            @Override protected List<SecretsValidationService.ValidationResult> call() {
                return secretsValidationService.validate(leaks);
            }
        };
        setStatus.accept("Validating " + leaks.size() + " leaked secret(s)...");
        progressBar.setVisible(true);
        task.setOnSucceeded(ev -> {
            progressBar.setVisible(false);
            List<SecretsValidationService.ValidationResult> validationResults = task.getValue();
            console.appendRawText("\n" + SecretsValidationService.formatReport(validationResults, source) + "\n");
            setStatus.accept("Secrets validation completed: " + validationResults.size() + " pattern match(es).");
        });
        task.setOnFailed(ev -> {
            progressBar.setVisible(false);
            setStatus.accept("Secrets validation failed: " + msg(task));
        });
        daemon(task, "secrets-validation");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void bindProgress(Task<?> task) {
        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
    }

    private void unbindProgress() {
        progressBar.progressProperty().unbind();
        progressBar.setVisible(false);
    }

    private static String msg(Task<?> task) {
        Throwable ex = task.getException();
        return ex != null ? ex.getMessage() : "unknown error";
    }

    private static void daemon(Task<?> task, String name) {
        Thread t = new Thread(task, name);
        t.setDaemon(true);
        t.start();
    }

    // ── Static URL helpers (shared with controller) ──────────────────────────

    public static String ensureHttpUrl(String input) {
        if (input == null || input.isBlank()) return "";
        String host = extractHostOrDomain(input);
        if (host.isBlank()) return "";
        if (input.startsWith("http://") || input.startsWith("https://")) return input.trim();
        return "https://" + host;
    }

    public static String extractHostOrDomain(String input) {
        if (input == null) return "";
        String trimmed = input.trim();
        if (trimmed.isBlank()) return "";
        try {
            String candidate = trimmed.startsWith("http://") || trimmed.startsWith("https://")
                ? trimmed : "https://" + trimmed;
            URI uri = new URI(candidate);
            if (uri.getHost() != null) return uri.getHost().trim();
        } catch (URISyntaxException ignored) {}
        return trimmed;
    }

    // ── Builder ──────────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private Supplier<String>  targetUrlSupplier;
        private Supplier<String>  targetHostSupplier;
        private Supplier<String>  consoleTextSupplier;
        private Supplier<Integer> firstScanPortSupplier;
        private Supplier<Integer> tlsPortSupplier;
        private ConsoleViewManager console;
        private ProgressBar        progressBar;
        private Consumer<String>   setStatus;
        private XssDetector               xssDetector;
        private CorsChecker               corsChecker;
        private JwtAnalyzer               jwtAnalyzer;
        private SsrfDetector              ssrfDetector;
        private DirectoryBruteforcer      dirBruteforcer;
        private WhoisService              whoisService;
        private SslTlsAuditor             sslTlsAuditor;
        private GraphqlScanner            graphqlScanner;
        private XxeDetector               xxeDetector;
        private SubdomainTakeoverChecker  takeoverChecker;
        private DnsZoneTransferService    dnsAxfrService;
        private Log4ShellChecker          log4ShellChecker;
        private Spring4ShellChecker       spring4ShellChecker;
        private WebSocketDetector         webSocketDetector;
        private HttpProtocolDetector      httpProtocolDetector;
        private AsnLookupService          asnLookupService;
        private HeartbleedChecker         heartbleedChecker;
        private ApiSecurityModeService    apiSecurityModeService;
        private PassiveReconService       passiveReconService;
        private SecretsValidationService  secretsValidationService;
        private Supplier<List<LeakInfo>>  leaksSupplier;

        public Builder targetUrlSupplier(Supplier<String> s)      { targetUrlSupplier = s; return this; }
        public Builder targetHostSupplier(Supplier<String> s)     { targetHostSupplier = s; return this; }
        public Builder consoleTextSupplier(Supplier<String> s)    { consoleTextSupplier = s; return this; }
        public Builder firstScanPortSupplier(Supplier<Integer> s) { firstScanPortSupplier = s; return this; }
        public Builder tlsPortSupplier(Supplier<Integer> s)       { tlsPortSupplier = s; return this; }
        public Builder console(ConsoleViewManager c)               { console = c; return this; }
        public Builder progressBar(ProgressBar p)                  { progressBar = p; return this; }
        public Builder setStatus(Consumer<String> s)               { setStatus = s; return this; }
        public Builder xssDetector(XssDetector x)                 { xssDetector = x; return this; }
        public Builder corsChecker(CorsChecker c)                 { corsChecker = c; return this; }
        public Builder jwtAnalyzer(JwtAnalyzer j)                 { jwtAnalyzer = j; return this; }
        public Builder ssrfDetector(SsrfDetector s)               { ssrfDetector = s; return this; }
        public Builder dirBruteforcer(DirectoryBruteforcer d)     { dirBruteforcer = d; return this; }
        public Builder whoisService(WhoisService w)               { whoisService = w; return this; }
        public Builder sslTlsAuditor(SslTlsAuditor s)            { sslTlsAuditor = s; return this; }
        public Builder graphqlScanner(GraphqlScanner g)           { graphqlScanner = g; return this; }
        public Builder xxeDetector(XxeDetector x)                 { xxeDetector = x; return this; }
        public Builder takeoverChecker(SubdomainTakeoverChecker t) { takeoverChecker = t; return this; }
        public Builder dnsAxfrService(DnsZoneTransferService d)   { dnsAxfrService = d; return this; }
        public Builder log4ShellChecker(Log4ShellChecker l)       { log4ShellChecker = l; return this; }
        public Builder spring4ShellChecker(Spring4ShellChecker s) { spring4ShellChecker = s; return this; }
        public Builder webSocketDetector(WebSocketDetector w)     { webSocketDetector = w; return this; }
        public Builder httpProtocolDetector(HttpProtocolDetector h) { httpProtocolDetector = h; return this; }
        public Builder asnLookupService(AsnLookupService a)       { asnLookupService = a; return this; }
        public Builder heartbleedChecker(HeartbleedChecker h)     { heartbleedChecker = h; return this; }
        public Builder apiSecurityModeService(ApiSecurityModeService a) { apiSecurityModeService = a; return this; }
        public Builder passiveReconService(PassiveReconService p)  { passiveReconService = p; return this; }
        public Builder secretsValidationService(SecretsValidationService s) { secretsValidationService = s; return this; }
        public Builder leaksSupplier(Supplier<List<LeakInfo>> s)  { leaksSupplier = s; return this; }

        public SecurityAnalysisHandler build() { return new SecurityAnalysisHandler(this); }
    }
}
