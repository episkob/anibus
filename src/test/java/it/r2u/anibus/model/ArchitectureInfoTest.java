package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ArchitectureInfoTest {

    @Test
    void infrastructureHasFindingsOnlyForKnownSignals() {
        ArchitectureInfo.InfrastructureInfo empty = new ArchitectureInfo.InfrastructureInfo(
                ArchitectureInfo.InfrastructureInfo.ContainerRuntime.NONE,
                0,
                ArchitectureInfo.InfrastructureInfo.Orchestrator.UNKNOWN,
                0,
                ArchitectureInfo.InfrastructureInfo.ProxyGateway.NONE,
                List.of());
        assertFalse(empty.hasFindings());

        ArchitectureInfo.InfrastructureInfo withFindings = new ArchitectureInfo.InfrastructureInfo(
                ArchitectureInfo.InfrastructureInfo.ContainerRuntime.DOCKER,
                0.9,
                ArchitectureInfo.InfrastructureInfo.Orchestrator.KUBERNETES,
                0.8,
                ArchitectureInfo.InfrastructureInfo.ProxyGateway.NGINX,
                List.of("docker-compose", "k8s ingress"));
        assertTrue(withFindings.hasFindings());
    }

    @Test
    void toStringPrefersCmsThenFrameworkAndShowsConfidence() {
        ArchitectureInfo cms = new ArchitectureInfo(
                ArchitectureInfo.ArchitecturePattern.MICROSERVICES,
                ArchitectureInfo.StateManagement.REDUX,
                ArchitectureInfo.Framework.REACT,
                ArchitectureInfo.CMS.WORDPRESS,
                List.of("api"),
                Map.of("env", "prod"),
                List.of("auth"),
                "ctx",
                0.91);

        String cmsText = cms.toString();
        assertTrue(cmsText.contains("WORDPRESS CMS"));
        assertTrue(cmsText.contains("using MICROSERVICES"));
        assertTrue(cmsText.contains("with REDUX"));
        assertTrue(cmsText.contains("91% confidence"));

        ArchitectureInfo framework = new ArchitectureInfo(
                ArchitectureInfo.ArchitecturePattern.MONOLITH,
                ArchitectureInfo.StateManagement.VANILLA,
                ArchitectureInfo.Framework.VUE,
                ArchitectureInfo.CMS.CUSTOM,
                List.of(),
                Map.of(),
                List.of(),
                "ctx",
                0.5);
        assertTrue(framework.toString().contains("VUE app"));

        ArchitectureInfo unknown = new ArchitectureInfo(
                ArchitectureInfo.ArchitecturePattern.UNKNOWN,
                ArchitectureInfo.StateManagement.UNKNOWN,
                ArchitectureInfo.Framework.UNKNOWN,
                ArchitectureInfo.CMS.UNKNOWN,
                List.of(),
                Map.of(),
                List.of(),
                "ctx",
                0.12);
        assertTrue(unknown.toString().contains("Web application"));
    }

    @Test
    void gettersReturnConfiguredValues() {
        ArchitectureInfo info = new ArchitectureInfo(
                ArchitectureInfo.ArchitecturePattern.BFF_PATTERN,
                ArchitectureInfo.StateManagement.PINIA,
                ArchitectureInfo.Framework.VUE,
                ArchitectureInfo.CMS.STRAPI,
                List.of("users", "billing"),
                Map.of("region", "eu"),
                List.of("jwt", "ratelimit"),
                "evidence",
                0.77);

        assertEquals(ArchitectureInfo.ArchitecturePattern.BFF_PATTERN, info.getPattern());
        assertEquals(ArchitectureInfo.StateManagement.PINIA, info.getStateManagement());
        assertEquals(ArchitectureInfo.Framework.VUE, info.getFramework());
        assertEquals(ArchitectureInfo.CMS.STRAPI, info.getCms());
        assertEquals(List.of("users", "billing"), info.getServices());
        assertEquals("eu", info.getConfigurations().get("region"));
        assertEquals(List.of("jwt", "ratelimit"), info.getMiddlewares());
        assertEquals("evidence", info.getEvidence());
        assertEquals(0.77, info.getPatternConfidence());
    }
}