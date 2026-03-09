package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents information about an API endpoint discovered in JavaScript source code.
 */
public class EndpointInfo {
    private final String url;
    private final String baseUrl;
    private final String path;
    private final String httpMethod;
    private final List<String> parameters;
    private final Map<String, String> headers;
    private final String context;
    private final boolean isDynamic;

    public EndpointInfo(String url, String baseUrl, String path, String httpMethod, 
                       List<String> parameters, Map<String, String> headers, 
                       String context, boolean isDynamic) {
        this.url = url;
        this.baseUrl = baseUrl;
        this.path = path;
        this.httpMethod = httpMethod;
        this.parameters = parameters;
        this.headers = headers;
        this.context = context;
        this.isDynamic = isDynamic;
    }

    public String getUrl() { return url; }
    public String getBaseUrl() { return baseUrl; }
    public String getPath() { return path; }
    public String getHttpMethod() { return httpMethod; }
    public List<String> getParameters() { return parameters; }
    public Map<String, String> getHeaders() { return headers; }
    public String getContext() { return context; }
    public boolean isDynamic() { return isDynamic; }

    @Override
    public String toString() {
        return httpMethod + " " + url + (isDynamic ? " (dynamic)" : "");
    }
}