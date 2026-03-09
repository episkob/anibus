package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents inferred database schema information from JavaScript source code.
 */
public class DatabaseSchemaInfo {
    
    public enum DatabaseType {
        SQL, MONGODB, REDIS, ELASTICSEARCH, UNKNOWN
    }

    private final String tableName;
    private final DatabaseType databaseType;
    private final Map<String, String> columns; // column name -> inferred type
    private final List<String> relationships;
    private final List<String> indexes;
    private final String evidence; // Code context that suggests this schema
    private final double confidence; // Confidence level 0.0-1.0

    public DatabaseSchemaInfo(String tableName, DatabaseType databaseType, 
                            Map<String, String> columns, List<String> relationships,
                            List<String> indexes, String evidence, double confidence) {
        this.tableName = tableName;
        this.databaseType = databaseType;
        this.columns = columns;
        this.relationships = relationships;
        this.indexes = indexes;
        this.evidence = evidence;
        this.confidence = confidence;
    }

    public String getTableName() { return tableName; }
    public DatabaseType getDatabaseType() { return databaseType; }
    public Map<String, String> getColumns() { return columns; }
    public List<String> getRelationships() { return relationships; }
    public List<String> getIndexes() { return indexes; }
    public String getEvidence() { return evidence; }
    public double getConfidence() { return confidence; }

    @Override
    public String toString() {
        return databaseType + " Table: " + tableName + " (" + columns.size() + " columns, " + 
               String.format("%.0f", confidence * 100) + "% confidence)";
    }
}