package it.r2u.anibus.service;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import it.r2u.anibus.model.LeakInfo;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;

class JavaScriptSecurityAnalyzerServiceInferenceTest {

    @Test
    void infersAuthFromApiPath() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        LeakInfo leak = new LeakInfo(
            "KV Pair: Username + Password",
            "Username: admin | Password: realSecret123",
            "POST /api/auth/login",
            8,
            null,
            false
        );

        String service = invokeInferService(analyzer, leak);
        assertEquals("auth", service);
    }

    @Test
    void normalizesBillingAliasToPayment() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        LeakInfo leak = new LeakInfo(
            "Token→Endpoint",
            "tokenVar → /api/billing/invoice",
            "axios.post('/api/billing/invoice')",
            6,
            null,
            false
        );

        String service = invokeInferService(analyzer, leak);
        assertEquals("payment", service);
    }

    private static String invokeInferService(JavaScriptSecurityAnalyzer analyzer,
                                             LeakInfo leak) throws Exception {
        Method inferService = JavaScriptSecurityAnalyzer.class
            .getDeclaredMethod("inferService", LeakInfo.class);
        inferService.setAccessible(true);
        return (String) inferService.invoke(analyzer, leak);
    }

    @Test
    @SuppressWarnings("unchecked")
    void extractsHistoryLocationsIntoSensitiveLeaks() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        Method findSensitive = JavaScriptSecurityAnalyzer.class.getDeclaredMethod(
            "findSensitiveInformation",
            String.class,
            JavaScriptSecurityAnalyzer.AnalysisDepth.class
        );
        findSensitive.setAccessible(true);

        String js = "const state = { historyLocations: ['/feed','/auth/login','/payment/checkout'] };";
        List<LeakInfo> leaks = (List<LeakInfo>) findSensitive.invoke(
            analyzer, js, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

        assertTrue(leaks.stream().anyMatch(l -> "History Locations".equals(l.getType())));
        assertTrue(leaks.stream().anyMatch(l -> l.getValue() != null && l.getValue().contains("/auth/login")));
    }

    @Test
    @SuppressWarnings("unchecked")
    void infersCrossLinkTargetForProductForeignKey() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        Method inferRelationships = JavaScriptSecurityAnalyzer.class
            .getDeclaredMethod("inferRelationships", Map.class);
        inferRelationships.setAccessible(true);

        Map<String, String> props = new HashMap<>();
        props.put("product_id", "number");
        props.put("cart_id", "number");

        List<String> relationships = (List<String>) inferRelationships.invoke(analyzer, props);
        assertTrue(relationships.stream().anyMatch(r -> r.contains("product_id") && r.contains("products")));
        assertTrue(relationships.stream().anyMatch(r -> r.contains("cart_id") && r.contains("carts")));
    }

    @Test
    @SuppressWarnings("unchecked")
    void extractsTypedVksdkTokenMarkers() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        Method findSensitive = JavaScriptSecurityAnalyzer.class.getDeclaredMethod(
            "findSensitiveInformation",
            String.class,
            JavaScriptSecurityAnalyzer.AnalysisDepth.class
        );
        findSensitive.setAccessible(true);

        String js = "const tokenType = 'VKSDKGeneralSuperAppToken';";
        List<LeakInfo> leaks = (List<LeakInfo>) findSensitive.invoke(
            analyzer, js, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

        assertTrue(leaks.stream().anyMatch(l -> "Typed Token".equals(l.getType())));
        assertTrue(leaks.stream().anyMatch(l -> l.getValue() != null && l.getValue().contains("VKSDKGeneralSuperAppToken")));
    }

    @Test
    @SuppressWarnings("unchecked")
    void extractsPasswordHierarchyAndValidationSignals() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        Method findSensitive = JavaScriptSecurityAnalyzer.class.getDeclaredMethod(
            "findSensitiveInformation",
            String.class,
            JavaScriptSecurityAnalyzer.AnalysisDepth.class
        );
        findSensitive.setAccessible(true);

        String js = "const OLD_PASSWORD='old123'; const status='incorrect_password';";
        List<LeakInfo> leaks = (List<LeakInfo>) findSensitive.invoke(
            analyzer, js, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

        assertTrue(leaks.stream().anyMatch(l -> "Password Hierarchy".equals(l.getType())));
        assertTrue(leaks.stream().anyMatch(l -> "Password Validation Status".equals(l.getType())));
    }

    @Test
    @SuppressWarnings("unchecked")
    void extractsSessionIdentifierBundleWithRegistrationContext() throws Exception {
        JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();
        Method findSensitive = JavaScriptSecurityAnalyzer.class.getDeclaredMethod(
            "findSensitiveInformation",
            String.class,
            JavaScriptSecurityAnalyzer.AnalysisDepth.class
        );
        findSensitive.setAccessible(true);

        String js = "const p={uuid:'123e4567-e89b-12d3-a456-426614174000',user_id:'42',email:'u@x.com'};";
        List<LeakInfo> leaks = (List<LeakInfo>) findSensitive.invoke(
            analyzer, js, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

        assertTrue(leaks.stream().anyMatch(l -> "Session Identifier Bundle".equals(l.getType())));
    }
}
