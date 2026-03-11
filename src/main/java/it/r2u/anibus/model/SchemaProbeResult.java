package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents the result of probing a discovered database schema
 * by querying correlated API endpoints and extracting real data.
 */
public class SchemaProbeResult {

    private final String schemaName;
    private final List<ProbeHit> hits;

    public SchemaProbeResult(String schemaName, List<ProbeHit> hits) {
        this.schemaName = schemaName;
        this.hits = hits;
    }

    public String getSchemaName() { return schemaName; }
    public List<ProbeHit> getHits() { return hits; }
    public boolean hasData() { return hits != null && !hits.isEmpty(); }

    /**
     * A single successful data fetch from an endpoint.
     */
    public static class ProbeHit {
        private final String probeUrl;
        private final int statusCode;
        private final Map<String, String> matchedValues;   // column name -> actual value
        private final int totalResponseKeys;

        public ProbeHit(String probeUrl, int statusCode,
                        Map<String, String> matchedValues, int totalResponseKeys) {
            this.probeUrl = probeUrl;
            this.statusCode = statusCode;
            this.matchedValues = matchedValues;
            this.totalResponseKeys = totalResponseKeys;
        }

        public String getProbeUrl() { return probeUrl; }
        public int getStatusCode() { return statusCode; }
        public Map<String, String> getMatchedValues() { return matchedValues; }
        public int getTotalResponseKeys() { return totalResponseKeys; }
    }
}
