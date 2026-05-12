package it.r2u.anibus.handlers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.service.network.proxy.ProxyNode;
import it.r2u.anibus.service.network.proxy.ProxyRoutingService;
import it.r2u.anibus.ui.LanguageManager;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

/**
 * Handles all proxy tab UI: harvesting, chain builder DnD, proxy log,
 * active proxy selection, chain display, and proxy rotation.
 */
public class ProxyTabHandler {

    // ── UI components ─────────────────────────────────────────────────────────
    private final TextArea proxyLogArea;
    private final Label activeProxyLabel;
    private final Circle proxyStatusDot;
    private final Button startProxyButton;
    private final Button clearProxyButton;
    private final Button loadProxyButton;
    private final Button rotateProxyButton;
    private final Label proxyStatCandidates;
    private final Label proxyStatLive;
    private final Label proxyStatCountries;
    private final Label proxyPhaseLabel;
    private final ProgressBar proxyProgressBar;
    private final TextArea chainDisplayArea;
    private final VBox chainDisplayCard;
    private final ListView<String> proxyAvailableListView;
    private final ListView<String> proxyChainListView;
    private final TextField hostTextField;
    private final Label resolvedHostLabel;
    private final HostResolver hostResolver;
    private final CheckBox proxyTransportAutoCheckBox;
    private final CheckBox proxyTransportTorCheckBox;
    private final CheckBox proxyTransportOtherOnionCheckBox;

    // ── State ─────────────────────────────────────────────────────────────────
    private final List<ProxyNode> currentProxyChain = new ArrayList<>();
    private final Map<String, ProxyNode> proxyVisualMap = new LinkedHashMap<>();
    private ProxyRoutingService proxyRoutingService;
    private ProxyNode currentActiveProxy = null;
    private boolean proxyHarvesting = false;

    public ProxyTabHandler(
            TextArea proxyLogArea,
            Label activeProxyLabel,
            Circle proxyStatusDot,
            Button startProxyButton,
            Button clearProxyButton,
            Button loadProxyButton,
            Button rotateProxyButton,
            Label proxyStatCandidates,
            Label proxyStatLive,
            Label proxyStatCountries,
            Label proxyPhaseLabel,
            ProgressBar proxyProgressBar,
            TextArea chainDisplayArea,
            VBox chainDisplayCard,
            ListView<String> proxyAvailableListView,
            ListView<String> proxyChainListView,
            TextField hostTextField,
            Label resolvedHostLabel,
            HostResolver hostResolver,
            CheckBox proxyTransportAutoCheckBox,
            CheckBox proxyTransportTorCheckBox,
            CheckBox proxyTransportOtherOnionCheckBox) {
        this.proxyLogArea = proxyLogArea;
        this.activeProxyLabel = activeProxyLabel;
        this.proxyStatusDot = proxyStatusDot;
        this.startProxyButton = startProxyButton;
        this.clearProxyButton = clearProxyButton;
        this.loadProxyButton = loadProxyButton;
        this.rotateProxyButton = rotateProxyButton;
        this.proxyStatCandidates = proxyStatCandidates;
        this.proxyStatLive = proxyStatLive;
        this.proxyStatCountries = proxyStatCountries;
        this.proxyPhaseLabel = proxyPhaseLabel;
        this.proxyProgressBar = proxyProgressBar;
        this.chainDisplayArea = chainDisplayArea;
        this.chainDisplayCard = chainDisplayCard;
        this.proxyAvailableListView = proxyAvailableListView;
        this.proxyChainListView = proxyChainListView;
        this.hostTextField = hostTextField;
        this.resolvedHostLabel = resolvedHostLabel;
        this.hostResolver = hostResolver;
        this.proxyTransportAutoCheckBox = proxyTransportAutoCheckBox;
        this.proxyTransportTorCheckBox = proxyTransportTorCheckBox;
        this.proxyTransportOtherOnionCheckBox = proxyTransportOtherOnionCheckBox;
    }

    // ── Setup ─────────────────────────────────────────────────────────────────

    /** Set up the drag-and-drop chain builder between the two list views. */
    public void setup() {
        setupProxyChainBuilderDnD();
        setupTransportControls();
    }

    // ── Public state accessors ────────────────────────────────────────────────

    public ProxyRoutingService getProxyRoutingService() { return proxyRoutingService; }
    public ProxyNode getCurrentActiveProxy() { return currentActiveProxy; }
    public List<ProxyNode> getCurrentProxyChain() { return currentProxyChain; }
    public boolean isProxyHarvesting() { return proxyHarvesting; }

    // ── Proxy harvest / load / clear ──────────────────────────────────────────

    public void onStartProxy() {
        LanguageManager lm = LanguageManager.getInstance();
        startProxyButton.setDisable(true);
        clearProxyButton.setText(lm.get("btn.stopHarvesting"));
        proxyPhaseLabel.setText("HARVESTING");
        proxyHarvesting = true;
        proxyLogArea.clear();
        appendProxyLog("═══════════════════════════════════════\n");
        appendProxyLog("  ANIBUS PROXY HARVESTER\n");
        appendProxyLog("═══════════════════════════════════════\n");

        proxyRoutingService = new ProxyRoutingService();
        proxyRoutingService.setLogCallback(
                msg -> Platform.runLater(() -> appendProxyLog(msg)));
        proxyRoutingService.setStatsCallback(stats -> Platform.runLater(() -> {
            if (stats[0] > 0) proxyStatCandidates.setText(String.valueOf(stats[0]));
            proxyStatLive.setText(String.valueOf(stats[1]));
            proxyStatCountries.setText(String.valueOf(stats[2]));
        }));
        proxyRoutingService.setProgressCallback(
                val -> Platform.runLater(() -> {
                    proxyProgressBar.setVisible(true);
                    proxyProgressBar.setProgress(val);
                }));

        proxyRoutingService.initializeAsync().thenRun(() -> Platform.runLater(() -> {
            proxyHarvesting = false;
            startProxyButton.setDisable(false);
            clearProxyButton.setText(lm.get("btn.clear"));
            proxyProgressBar.setVisible(false);
            if (proxyRoutingService.isReady()) {
                applyOptionalOnionTransport();
                proxyPhaseLabel.setText("READY");
                appendProxyLog("\n✓ Pool ready — " + proxyRoutingService.poolSize() + " live proxies\n");
                refreshAvailableProxies();
                if (proxyRoutingService.hasSavedPool()) {
                    loadProxyButton.setText(LanguageManager.getInstance().get("btn.loadFromFile") + " ✓");
                    loadProxyButton.setTooltip(new Tooltip(
                            "Cached pool: " + proxyRoutingService.savedPoolPath()));
                }
                String target = hostTextField.getText().trim();
                if (!target.isBlank()) {
                    proxyRoutingService.selectStableProxy(target).ifPresentOrElse(
                        p -> {
                            updateActiveProxy(p);
                            appendProxyLog("\n● Active proxy: "
                                    + p.host() + ":" + p.port()
                                    + "  [" + p.type() + "]  "
                                    + p.countryCode() + "  ~  " + p.latencyMs() + " ms\n");
                        },
                        () -> appendProxyLog("\n✗ No suitable proxy for target\n")
                    );
                }
            } else {
                appendProxyLog("\n✗ No live proxies found\n");
                proxyPhaseLabel.setText("EMPTY");
                proxyStatusDot.setFill(javafx.scene.paint.Color.web("#ff453a"));
                activeProxyLabel.setText("No live proxies found");
                activeProxyLabel.setStyle("-fx-text-fill: #ff453a;");
            }
        }));
    }

    public void onLoadProxy() {
        proxyRoutingService = new ProxyRoutingService();
        proxyPhaseLabel.setText("LOADING");
        proxyRoutingService.setLogCallback(
                msg -> Platform.runLater(() -> appendProxyLog(msg)));
        proxyRoutingService.setStatsCallback(stats -> Platform.runLater(() -> {
            if (stats[0] > 0) proxyStatCandidates.setText(String.valueOf(stats[0]));
            proxyStatLive.setText(String.valueOf(stats[1]));
            proxyStatCountries.setText(String.valueOf(stats[2]));
        }));

        proxyLogArea.clear();
        appendProxyLog("═══════════════════════════════════════\n");
        appendProxyLog("  LOADING PROXY POOL FROM FILE\n");
        appendProxyLog("═══════════════════════════════════════\n");

        if (!proxyRoutingService.hasSavedPool()) {
            appendProxyLog("✗ No saved proxy file found.\n");
            appendProxyLog("  Run harvesting first to create one.\n");
            return;
        }

        int count = proxyRoutingService.loadFromFile();
        if (count == 0) {
            appendProxyLog("✗ File is empty or unreadable.\n");
            return;
        }

        applyOptionalOnionTransport();

        appendProxyLog("✓ Loaded " + count + " proxies\n");
        appendProxyLog("  File: " + proxyRoutingService.savedPoolPath() + "\n");
        proxyPhaseLabel.setText("READY");
        loadProxyButton.setDisable(true);
        refreshAvailableProxies();

        String target = hostTextField.getText().trim();
        if (!target.isBlank()) {
            String resolvedIp = hostResolver.extractIPFromResolvedText(resolvedHostLabel.getText());
            String geoTarget = resolvedIp.isBlank() ? target : resolvedIp;
            proxyRoutingService.selectStableProxy(geoTarget).ifPresentOrElse(
                p -> {
                    updateActiveProxy(p);
                    appendProxyLog("\n● Active proxy: "
                            + p.host() + ":" + p.port()
                            + "  [" + p.type() + "]  "
                            + p.countryCode() + "  ~  " + p.latencyMs() + " ms\n");
                },
                () -> appendProxyLog("\n✗ No suitable proxy for target\n")
            );
        }
    }

    public void onClearProxyLog() {
        LanguageManager lm = LanguageManager.getInstance();
        if (proxyHarvesting && proxyRoutingService != null) {
            proxyRoutingService.cancel();
            proxyHarvesting = false;
            startProxyButton.setDisable(false);
            clearProxyButton.setText(lm.get("btn.clear"));
            proxyPhaseLabel.setText("CANCELLED");
            appendProxyLog("\n■ Harvesting stopped by user.\n");
            return;
        }
        proxyLogArea.clear();
        proxyStatCandidates.setText("—");
        proxyStatLive.setText("—");
        proxyStatCountries.setText("—");
        proxyPhaseLabel.setText("IDLE");
        proxyProgressBar.setVisible(false);
        proxyStatusDot.setFill(javafx.scene.paint.Color.web("#8E8E93"));
        activeProxyLabel.setText("No active proxy");
        activeProxyLabel.setStyle("");
        currentActiveProxy = null;
        currentProxyChain.clear();
        if (proxyRoutingService != null) {
            proxyRoutingService.resetCountryQuarantine();
        }
        if (proxyChainListView != null) {
            proxyChainListView.getItems().clear();
        }
        displayProxyChain();
        loadProxyButton.setDisable(false);
    }

    // ── Proxy rotation & chain builder ────────────────────────────────────────

    public void onRotateProxy() {
        if (proxyRoutingService == null || !proxyRoutingService.isReady()) return;
        String resolvedIp = hostResolver.extractIPFromResolvedText(resolvedHostLabel.getText());
        String geoTarget = resolvedIp.isBlank() ? hostTextField.getText().trim() : resolvedIp;
        ProxyNode prev = currentActiveProxy;
        if (prev != null) proxyRoutingService.failover(prev, geoTarget).ifPresentOrElse(
            p -> {
                updateActiveProxy(p);
                appendProxyLog("\n↻ Rotated to: " + p.host() + ":" + p.port()
                        + "  [" + p.type() + "]  " + p.countryCode()
                        + "  ~  " + p.latencyMs() + " ms\n");
            },
            () -> {
                proxyRoutingService.selectStableProxy(geoTarget).ifPresent(p -> {
                    updateActiveProxy(p);
                    appendProxyLog("\n↻ Rotated to: " + p.host() + ":" + p.port()
                            + "  [" + p.type() + "]  " + p.countryCode()
                            + "  ~  " + p.latencyMs() + " ms\n");
                });
            });
        else
            proxyRoutingService.selectStableProxy(geoTarget).ifPresent(this::updateActiveProxy);
    }

    public void onBuildChain() {
        LanguageManager lm = LanguageManager.getInstance();

        if (proxyRoutingService == null || !proxyRoutingService.isReady()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle(lm.get("dialog.chainBuilder.emptyTitle"));
            alert.setHeaderText(lm.get("dialog.chainBuilder.emptyHeader"));
            alert.setContentText(lm.get("dialog.chainBuilder.emptyContent"));
            alert.showAndWait();
            return;
        }

        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(lm.get("dialog.chainBuilder.title"));
        alert.setHeaderText(lm.get("dialog.chainBuilder.header"));
        String content = lm.get("dialog.chainBuilder.content");
        alert.setContentText(String.format(content, proxyRoutingService.poolSize()));
        alert.showAndWait();

        if (proxyChainListView != null && !proxyChainListView.getItems().isEmpty()) {
            syncChainFromListView();
            appendProxyLog("\n● Chain updated via drag-and-drop builder\n");
            return;
        }

        if (currentActiveProxy != null) {
            currentProxyChain.clear();
            currentProxyChain.add(currentActiveProxy);
            if (proxyChainListView != null) {
                String label = formatProxyNodeDisplay(currentActiveProxy);
                proxyVisualMap.put(label, currentActiveProxy);
                proxyChainListView.getItems().setAll(label);
            }
            displayProxyChain();
            String chainMsg = String.format(
                lm.get("dialog.chain.initialized"),
                currentActiveProxy.host(),
                currentActiveProxy.port()
            );
            appendProxyLog("\n" + chainMsg + "\n");
        }
    }

    // ── Helper methods ────────────────────────────────────────────────────────

    public void updateActiveProxy(ProxyNode p) {
        currentActiveProxy = p;
        proxyStatusDot.setFill(javafx.scene.paint.Color.web("#30d158"));
        activeProxyLabel.setText(
                p.host() + ":" + p.port()
                + "  [" + p.type() + "]  "
                + p.countryCode() + "  ~  " + p.latencyMs() + " ms");
        activeProxyLabel.setStyle("-fx-text-fill: #30d158; -fx-font-weight: 600;");
        rotateProxyButton.setVisible(true);
        rotateProxyButton.setManaged(true);
    }

    public void autoSelectProxyForCurrentTarget() {
        if (proxyRoutingService == null || !proxyRoutingService.isReady()) return;
        String resolvedIp = hostResolver.extractIPFromResolvedText(resolvedHostLabel.getText());
        if (resolvedIp.isBlank()) return;
        proxyRoutingService.selectStableProxy(resolvedIp).ifPresent(p -> {
            if (currentActiveProxy == null
                    || !p.countryCode().equals(currentActiveProxy.countryCode())) {
                updateActiveProxy(p);
            }
        });
    }

    public void appendProxyLog(String text) {
        proxyLogArea.appendText(text);
        proxyLogArea.setScrollTop(Double.MAX_VALUE);
    }

    public void refreshAvailableProxies() {
        if (proxyAvailableListView == null || proxyRoutingService == null || !proxyRoutingService.isReady()) {
            return;
        }
        proxyVisualMap.clear();
        List<String> labels = proxyRoutingService.allProxies().stream()
            .sorted(java.util.Comparator.comparingLong(ProxyNode::latencyMs))
            .map(this::formatProxyNodeDisplay)
            .toList();
        proxyRoutingService.allProxies().forEach(node -> proxyVisualMap.put(formatProxyNodeDisplay(node), node));
        proxyAvailableListView.getItems().setAll(labels);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void setupProxyChainBuilderDnD() {
        if (proxyAvailableListView == null || proxyChainListView == null) {
            return;
        }

        proxyAvailableListView.setPlaceholder(new Label("Load/harvest proxies first"));
        proxyChainListView.setPlaceholder(new Label("Drag proxies here to build chain"));

        proxyAvailableListView.setOnDragDetected(event -> {
            String selected = proxyAvailableListView.getSelectionModel().getSelectedItem();
            if (selected == null) return;
            javafx.scene.input.Dragboard db = proxyAvailableListView.startDragAndDrop(javafx.scene.input.TransferMode.COPY);
            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
            content.putString(selected);
            db.setContent(content);
            event.consume();
        });

        proxyChainListView.setOnDragDetected(event -> {
            String selected = proxyChainListView.getSelectionModel().getSelectedItem();
            if (selected == null) return;
            javafx.scene.input.Dragboard db = proxyChainListView.startDragAndDrop(javafx.scene.input.TransferMode.MOVE);
            javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
            content.putString(selected);
            db.setContent(content);
            event.consume();
        });

        proxyChainListView.setOnDragOver(event -> {
            if (event.getDragboard().hasString()) {
                event.acceptTransferModes(javafx.scene.input.TransferMode.COPY_OR_MOVE);
            }
            event.consume();
        });

        proxyChainListView.setOnDragDropped(event -> {
            String item = event.getDragboard().getString();
            boolean completed = false;
            if (item != null && proxyVisualMap.containsKey(item)) {
                if (!proxyChainListView.getItems().contains(item)) {
                    proxyChainListView.getItems().add(item);
                }
                syncChainFromListView();
                completed = true;
            }
            event.setDropCompleted(completed);
            event.consume();
        });

        proxyChainListView.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) {
                String selected = proxyChainListView.getSelectionModel().getSelectedItem();
                if (selected != null) {
                    proxyChainListView.getItems().remove(selected);
                    syncChainFromListView();
                }
            }
        });
    }

    private void setupTransportControls() {
        if (proxyTransportAutoCheckBox == null
                || proxyTransportTorCheckBox == null
                || proxyTransportOtherOnionCheckBox == null) {
            return;
        }

        Runnable sync = () -> {
            if (proxyTransportAutoCheckBox.isSelected()) {
                proxyTransportTorCheckBox.setSelected(true);
                proxyTransportOtherOnionCheckBox.setSelected(true);
            }
        };

        proxyTransportAutoCheckBox.setTooltip(new Tooltip(
            "Auto enables all local onion transports and chooses the best available."));
        proxyTransportTorCheckBox.setTooltip(new Tooltip(
            "Use local Tor endpoints (127.0.0.1:9150 and 127.0.0.1:9050)."));
        proxyTransportOtherOnionCheckBox.setTooltip(new Tooltip(
            "Use additional local onion-compatible endpoint (127.0.0.1:4447)."));

        sync.run();
        proxyTransportAutoCheckBox.selectedProperty().addListener((obs, oldV, newV) -> sync.run());

        // Keep controls readable and interactive: changing manual toggles exits AUTO mode.
        proxyTransportTorCheckBox.selectedProperty().addListener((obs, oldV, newV) -> {
            if (proxyTransportAutoCheckBox.isSelected() && !Boolean.TRUE.equals(newV)) {
                proxyTransportAutoCheckBox.setSelected(false);
            }
        });
        proxyTransportOtherOnionCheckBox.selectedProperty().addListener((obs, oldV, newV) -> {
            if (proxyTransportAutoCheckBox.isSelected() && !Boolean.TRUE.equals(newV)) {
                proxyTransportAutoCheckBox.setSelected(false);
            }
        });
    }

    private void applyOptionalOnionTransport() {
        if (proxyRoutingService == null) return;

        boolean auto = proxyTransportAutoCheckBox != null && proxyTransportAutoCheckBox.isSelected();
        boolean useTor = auto || (proxyTransportTorCheckBox != null && proxyTransportTorCheckBox.isSelected());
        boolean useOther = auto || (proxyTransportOtherOnionCheckBox != null && proxyTransportOtherOnionCheckBox.isSelected());

        if (!useTor && !useOther) return;

        int onionAdded = proxyRoutingService.enableOnionFallback(useTor, useOther);
        if (onionAdded > 0) {
            String mode = auto ? "AUTO" : (useTor && useOther ? "TOR+OTHER" : (useTor ? "TOR" : "OTHER"));
            appendProxyLog("\n✓ Onion transport enabled (" + mode + ") — "
                    + onionAdded + " local endpoint(s) added\n");
        } else {
            appendProxyLog("\n• Onion transport requested, but no local endpoint is reachable\n");
            appendProxyLog("  Checked: " + String.join(", ", selectedOnionEndpoints(useTor, useOther)) + "\n");
            appendProxyLog("  Tip: start Tor Browser or tor daemon and retry load/harvest.\n");
        }
    }

    private List<String> selectedOnionEndpoints(boolean useTor, boolean useOther) {
        List<String> endpoints = new ArrayList<>();
        if (useTor) {
            endpoints.add("127.0.0.1:9150");
            endpoints.add("127.0.0.1:9050");
        }
        if (useOther) {
            endpoints.add("127.0.0.1:4447");
        }
        return endpoints;
    }

    private void syncChainFromListView() {
        currentProxyChain.clear();
        for (String item : proxyChainListView.getItems()) {
            ProxyNode node = proxyVisualMap.get(item);
            if (node != null) {
                currentProxyChain.add(node);
            }
        }
        displayProxyChain();
    }

    private void displayProxyChain() {
        if (currentProxyChain.isEmpty()) {
            chainDisplayCard.setVisible(false);
            chainDisplayCard.setManaged(false);
            return;
        }

        chainDisplayCard.setVisible(true);
        chainDisplayCard.setManaged(true);

        String chainDisplay = it.r2u.anibus.service.network.proxy.ProxyChainService.formatChain(currentProxyChain);
        chainDisplayArea.setText(chainDisplay);
        if (proxyChainListView != null) {
            List<String> labels = currentProxyChain.stream().map(this::formatProxyNodeDisplay).toList();
            proxyChainListView.getItems().setAll(labels);
        }
    }

    private String formatProxyNodeDisplay(ProxyNode node) {
        return node.host() + ":" + node.port() + " [" + node.type() + "] " + node.countryCode() + " ~ " + node.latencyMs() + "ms";
    }
}
