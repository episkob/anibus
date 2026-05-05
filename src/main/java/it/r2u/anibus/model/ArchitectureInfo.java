package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents architectural insights discovered from JavaScript source code analysis.
 */
public class ArchitectureInfo {

    /** Infrastructure inference result from JS/HTML source analysis. */
    public static class InfrastructureInfo {

        public enum ContainerRuntime { DOCKER, PODMAN, NONE, UNKNOWN }
        public enum Orchestrator    { KUBERNETES, SWARM, NOMAD, NONE, UNKNOWN }
        public enum ProxyGateway    { NGINX, HAPROXY, ENVOY, TRAEFIK, ISTIO, NONE, UNKNOWN }

        private final ContainerRuntime containerRuntime;
        private final double           containerConfidence;
        private final Orchestrator     orchestrator;
        private final double           orchestratorConfidence;
        private final ProxyGateway     proxyGateway;
        private final List<String>     evidence;

        public InfrastructureInfo(ContainerRuntime containerRuntime, double containerConfidence,
                                  Orchestrator orchestrator,    double orchestratorConfidence,
                                  ProxyGateway proxyGateway,   List<String> evidence) {
            this.containerRuntime       = containerRuntime;
            this.containerConfidence    = containerConfidence;
            this.orchestrator           = orchestrator;
            this.orchestratorConfidence = orchestratorConfidence;
            this.proxyGateway           = proxyGateway;
            this.evidence               = evidence;
        }

        public ContainerRuntime getContainerRuntime()       { return containerRuntime; }
        public double           getContainerConfidence()    { return containerConfidence; }
        public Orchestrator     getOrchestrator()           { return orchestrator; }
        public double           getOrchestratorConfidence() { return orchestratorConfidence; }
        public ProxyGateway     getProxyGateway()           { return proxyGateway; }
        public List<String>     getEvidence()               { return evidence; }

        public boolean hasFindings() {
            return containerRuntime != ContainerRuntime.NONE && containerRuntime != ContainerRuntime.UNKNOWN
                || orchestrator != Orchestrator.NONE && orchestrator != Orchestrator.UNKNOWN
                || proxyGateway != ProxyGateway.NONE && proxyGateway != ProxyGateway.UNKNOWN;
        }
    }

    
    public enum ArchitecturePattern {
        DIRECT_API, PROXY_PATTERN, BFF_PATTERN, MICROSERVICES, SERVERLESS, MONOLITH, UNKNOWN
    }

    public enum StateManagement {
        REDUX, VUEX, MOBX, PINIA, ZUSTAND, RECOIL, JOTAI,
        NGRX, CONTEXT_API, VANILLA, UNKNOWN
    }

    /** Front-end JS/TS frameworks and meta-frameworks. */
    public enum Framework {
        // Big Three
        REACT, VUE, ANGULAR,
        // Meta / SSR
        NEXTJS_FW, NUXTJS_FW, REMIX, ASTRO, SVELTEKIT, QWIK,
        // Component / UI
        SVELTE, SOLID, PREACT, HTMX, ALPINE, EMBER, BACKBONE,
        // Mobile / Cross-platform
        REACT_NATIVE, IONIC, EXPO,
        // Misc
        VANILLA, UNKNOWN
    }

    /** CMS, headless CMS, e-commerce platforms, and back-end frameworks. */
    public enum CMS {
        // WordPress ecosystem
        WORDPRESS, WOOCOMMERCE,
        // PHP CMS
        DRUPAL, JOOMLA, TYPO3, MODX, OCTOBER_CMS, CONCRETE5, PROCESSWIRE,
        // PHP e-commerce
        MAGENTO, PRESTASHOP, OPENCART, OSCOMMERCE, WHMCS,
        // SaaS e-commerce
        SHOPIFY, BIGCOMMERCE, SQUARESPACE, WIX, WEBFLOW,
        // PHP full-stack
        LARAVEL, SYMFONY, CODEIGNITER, YAJRA, CAKEPHP, ZEND,
        // Python
        DJANGO, FLASK, FASTAPI, WAGTAIL,
        // Ruby
        RAILS, SPREE,
        // Node.js / JS back-end
        EXPRESS, NESTJS, STRAPI, KEYSTONE, GHOST,
        // Java / JVM
        SPRING, GRAILS,
        // .NET
        ASPNET, UMBRACO, ORCHARD,
        // Headless / API-first CMS
        CONTENTFUL, SANITY, PRISMIC, STORYBLOK, DIRECTUS, HYGRAPH,
        // Static site generators
        GATSBY, HUGO, JEKYLL, ELEVENTY, HEXO,
        // 1C-Bitrix (RU)
        BITRIX,
        // Generic / API
        CUSTOM, UNKNOWN
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
    private final InfrastructureInfo infrastructureInfo;

    public ArchitectureInfo(ArchitecturePattern pattern, StateManagement stateManagement, 
                          Framework framework, CMS cms, List<String> services, 
                          Map<String, String> configurations, List<String> middlewares,
                          String evidence, double patternConfidence) {
        this(pattern, stateManagement, framework, cms, services, configurations, middlewares,
             evidence, patternConfidence, null);
    }

    public ArchitectureInfo(ArchitecturePattern pattern, StateManagement stateManagement, 
                          Framework framework, CMS cms, List<String> services, 
                          Map<String, String> configurations, List<String> middlewares,
                          String evidence, double patternConfidence,
                          InfrastructureInfo infrastructureInfo) {
        this.pattern = pattern;
        this.stateManagement = stateManagement;
        this.framework = framework;
        this.cms = cms;
        this.services = services;
        this.configurations = configurations;
        this.middlewares = middlewares;
        this.evidence = evidence;
        this.patternConfidence = patternConfidence;
        this.infrastructureInfo = infrastructureInfo;
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
    public InfrastructureInfo getInfrastructureInfo() { return infrastructureInfo; }

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