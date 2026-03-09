package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

/**
 * Represents data structures identified in JavaScript source code.
 */
public class DataStructureInfo {
    
    public enum DataType {
        REQUEST_PAYLOAD, RESPONSE_MODEL, STATE_OBJECT, FORM_DATA, CONFIGURATION
    }

    private final String name;
    private final DataType type;
    private final Map<String, String> properties; // property name -> inferred type
    private final List<String> methods;
    private final String context;
    private final boolean isNested;

    public DataStructureInfo(String name, DataType type, Map<String, String> properties, 
                           List<String> methods, String context, boolean isNested) {
        this.name = name;
        this.type = type;
        this.properties = properties;
        this.methods = methods;
        this.context = context;
        this.isNested = isNested;
    }

    public String getName() { return name; }
    public DataType getType() { return type; }
    public Map<String, String> getProperties() { return properties; }
    public List<String> getMethods() { return methods; }
    public String getContext() { return context; }
    public boolean isNested() { return isNested; }

    @Override
    public String toString() {
        return type + ": " + name + " (" + properties.size() + " properties)";
    }
}