package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents architectural insights discovered from JavaScript source code analysis.
 */
public class ArchitectureInfo {
    
    public enum ArchitecturePattern {
        DIRECT_API, PROXY_PATTERN, BFF_PATTERN, MICROSERVICES, SERVERLESS, MONOLITH, UNKNOWN
    }

    public enum StateManagement {
        REDUX, VUEX, MOBX, CONTEXT_API, VANILLA, UNKNOWN
    }

    public enum Framework {
        REACT, VUE, ANGULAR, SVELTE, VANILLA, UNKNOWN
    }

    public enum CMS {
        WORDPRESS, DRUPAL, JOOMLA, MAGENTO, SHOPIFY, WOOCOMMERCE,
        LARAVEL, DJANGO, RAILS, NEXTJS, NUXTJS, GATSBY,
        STRAPI, CONTENTFUL, CUSTOM, UNKNOWN
    }

    private final ArchitecturePattern pattern;
    private final StateManagement stateManagement;
    private final Framework framework;
    private final CMS cms;
    private final List<String> services;
    private final Map<String, String> configurations;
    private final List<String> middlewares;
    private final String evidence;
    private final double patternConfidence;

    public ArchitectureInfo(ArchitecturePattern pattern, StateManagement stateManagement, 
                          Framework framework, CMS cms, List<String> services, 
                          Map<String, String> configurations, List<String> middlewares,
                          String evidence, double patternConfidence) {
        this.pattern = pattern;
        this.stateManagement = stateManagement;
        this.framework = framework;
        this.cms = cms;
        this.services = services;
        this.configurations = configurations;
        this.middlewares = middlewares;
        this.evidence = evidence;
        this.patternConfidence = patternConfidence;
    }

    public ArchitecturePattern getPattern() { return pattern; }
    public StateManagement getStateManagement() { return stateManagement; }
    public Framework getFramework() { return framework; }
    public CMS getCms() { return cms; }
    public List<String> getServices() { return services; }
    public Map<String, String> getConfigurations() { return configurations; }
    public List<String> getMiddlewares() { return middlewares; }
    public String getEvidence() { return evidence; }
    public double getPatternConfidence() { return patternConfidence; }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        
        if (cms != CMS.UNKNOWN && cms != CMS.CUSTOM) {
            result.append(cms.toString()).append(" CMS");
        } else if (framework != Framework.UNKNOWN && framework != Framework.VANILLA) {
            result.append(framework.toString()).append(" app");
        } else {
            result.append("Web application");
        }
        
        result.append(" using ").append(pattern);
        
        if (stateManagement != StateManagement.UNKNOWN && stateManagement != StateManagement.VANILLA) {
            result.append(" with ").append(stateManagement);
        }
        
        result.append(" (").append(String.format("%.0f", patternConfidence * 100)).append("% confidence)");
        
        return result.toString();
    }
}