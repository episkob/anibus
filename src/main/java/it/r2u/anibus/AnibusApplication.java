package it.r2u.anibus;

import java.io.IOException;

import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.service.analysis.CorsChecker;
import it.r2u.anibus.service.analysis.DirectoryBruteforcer;
import it.r2u.anibus.service.analysis.GraphqlScanner;
import it.r2u.anibus.service.analysis.HeartbleedChecker;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.analysis.JwtAnalyzer;
import it.r2u.anibus.service.analysis.Log4ShellChecker;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.SQLInjectionAnalyzer;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.analysis.Spring4ShellChecker;
import it.r2u.anibus.service.analysis.SsrfDetector;
import it.r2u.anibus.service.analysis.SubdomainTakeoverChecker;
import it.r2u.anibus.service.analysis.WebSocketDetector;
import it.r2u.anibus.service.analysis.XssDetector;
import it.r2u.anibus.service.analysis.XxeDetector;
import it.r2u.anibus.service.core.PortScannerService;
import it.r2u.anibus.service.core.ScanHistoryService;
import it.r2u.anibus.service.core.ScanSchedulerService;
import it.r2u.anibus.service.core.UdpScannerService;
import it.r2u.anibus.service.detection.EnhancedServiceDetector;
import it.r2u.anibus.service.export.ScanDiffService;
import it.r2u.anibus.service.network.AsnLookupService;
import it.r2u.anibus.service.network.DnsZoneTransferService;
import it.r2u.anibus.service.network.HttpProtocolDetector;
import it.r2u.anibus.service.network.SslTlsAuditor;
import it.r2u.anibus.service.network.SubdomainEnumerationService;
import it.r2u.anibus.service.network.WhoisService;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class AnibusApplication extends Application {

    private AnibusController controller;

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(AnibusApplication.class.getResource("hello-view.fxml"));
        AnibusController.CoreServices coreServices = new AnibusController.CoreServices(
            new PortScannerService(),
            new EnhancedServiceDetector(),
            new HostResolver(),
            new JavaScriptSecurityAnalyzer(),
            new SQLInjectionAnalyzer(),
            new SourceMapAnalyzer(),
            new ParamMinerService(),
            new SubdomainEnumerationService(),
            new UdpScannerService(),
            new ScanDiffService(),
            new ScanSchedulerService(),
            new ScanHistoryService(),
            new XssDetector(),
            new CorsChecker(),
            new JwtAnalyzer(),
            new SsrfDetector(),
            new DirectoryBruteforcer(),
            new WhoisService(),
            new SslTlsAuditor(),
            new GraphqlScanner(),
            new XxeDetector(),
            new SubdomainTakeoverChecker(),
            new DnsZoneTransferService(),
            new Log4ShellChecker(),
            new Spring4ShellChecker(),
            new WebSocketDetector(),
            new HttpProtocolDetector(),
            new AsnLookupService(),
            new HeartbleedChecker()
        );
        fxmlLoader.setControllerFactory(type -> {
            if (type == AnibusController.class) {
                return new AnibusController(coreServices);
            }
            try {
                return type.getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Cannot create controller: " + type.getName(), e);
            }
        });
        Scene scene = new Scene(fxmlLoader.load(), 1200, 800);

        // Apply Anibus design CSS
        scene.getStylesheets().add(AnibusApplication.class.getResource("anibus-style.css").toExternalForm());

        controller = fxmlLoader.getController();

        stage.setTitle("Anibus - Port Scanner");
        stage.setScene(scene);
        stage.setMinWidth(800);
        stage.setMinHeight(600);
        stage.show();
    }

    @Override
    public void stop() throws Exception {
        super.stop();
        if (controller != null) {
            controller.shutdownExecutor();
        }
    }

    public static void main(String[] args) {
        launch();
    }
}
