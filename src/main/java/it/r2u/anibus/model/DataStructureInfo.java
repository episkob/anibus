package it.r2u.anibus.model;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    /** Field names that are present in some but not all duplicate variants (marked "optional"). */
    private final Set<String> optionalProperties;

    public DataStructureInfo(String name, DataType type, Map<String, String> properties,
                             List<String> methods, String context, boolean isNested) {
        this(name, type, properties, methods, context, isNested, Collections.emptySet());
    }

    public DataStructureInfo(String name, DataType type, Map<String, String> properties,
                             List<String> methods, String context, boolean isNested,
                             Set<String> optionalProperties) {
        this.name = name;
        this.type = type;
        this.properties = properties;
        this.methods = methods;
        this.context = context;
        this.isNested = isNested;
        this.optionalProperties = optionalProperties != null ? optionalProperties : Collections.emptySet();
    }

    public String getName()                      { return name; }
    public DataType getType()                    { return type; }
    public Map<String, String> getProperties()   { return properties; }
    public List<String> getMethods()             { return methods; }
    public String getContext()                   { return context; }
    public boolean isNested()                    { return isNested; }
    public Set<String> getOptionalProperties()   { return optionalProperties; }
    public boolean isOptional(String propName)   { return optionalProperties.contains(propName); }

    /**
     * Merge two near-duplicate structures (same type, differ by exactly one field) into a single
     * structure. The field present in only one variant is marked as optional.
     */
    public static DataStructureInfo mergeOptional(DataStructureInfo a, DataStructureInfo b) {
        Map<String, String> merged = new java.util.LinkedHashMap<>(a.properties);
        Set<String> optional = new HashSet<>(a.optionalProperties);
        optional.addAll(b.optionalProperties);

        // Fields present in b but not in a → add + mark optional
        for (Map.Entry<String, String> entry : b.properties.entrySet()) {
            if (!merged.containsKey(entry.getKey())) {
                merged.put(entry.getKey(), entry.getValue());
                optional.add(entry.getKey());
            }
        }
        // Fields present in a but not in b → mark optional
        for (String key : a.properties.keySet()) {
            if (!b.properties.containsKey(key)) {
                optional.add(key);
            }
        }

        String mergedName = a.name; // keep first name
        return new DataStructureInfo(mergedName, a.type, merged, a.methods, a.context, a.isNested, optional);
    }

    @Override
    public String toString() {
        int optCount = optionalProperties.size();
        String suffix = optCount > 0 ? " [" + optCount + " optional]" : "";
        return type + ": " + name + " (" + properties.size() + " fields" + suffix + ")";
    }
}