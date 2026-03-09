package it.r2u.anibus.service;

import it.r2u.anibus.service.WebSourceAnalyzer.LeakInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Specialized analyzer for database credentials and connection strings in JavaScript.
 * Focuses on extracting login credentials, passwords, and database URLs with ranking.
 */
public class JavaScriptDatabaseAnalyzer {
    
    /**
     * Database credential patterns by priority (higher priority = more critical)
     */
    private static final DatabasePattern[] DB_PATTERNS = {
        // Priority 10 - Complete connection strings with credentials
        new DatabasePattern(
            Pattern.compile("(mongodb://[^:]+:[^@]+@[^/\"'\\s]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "MongoDB Connection with Credentials", 10),
        new DatabasePattern(
            Pattern.compile("(mysql://[^:]+:[^@]+@[^/\"'\\s]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "MySQL Connection with Credentials", 10),
        new DatabasePattern(
            Pattern.compile("(postgresql://[^:]+:[^@]+@[^/\"'\\s]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "PostgreSQL Connection with Credentials", 10),
        new DatabasePattern(
            Pattern.compile("(redis://[^:]*:[^@]*@[^/\"'\\s]+)", Pattern.CASE_INSENSITIVE),
            "Redis Connection with Credentials", 10),
            
        // Priority 9 - Database passwords in config
        new DatabasePattern(
            Pattern.compile("(?:password|pwd|passwd)\\s*[:=]\\s*['\"]([^'\"\\s]{4,})['\"]", Pattern.CASE_INSENSITIVE),
            "Database Password", 9),
        new DatabasePattern(
            Pattern.compile("(?:db_password|database_password|DB_PWD)\\s*[:=]\\s*['\"]([^'\"\\s]+)['\"]", Pattern.CASE_INSENSITIVE),
            "Database Password Variable", 9),
            
        // Priority 8 - Database usernames  
        new DatabasePattern(
            Pattern.compile("(?:username|user|uid)\\s*[:=]\\s*['\"]([^'\"\\s]{3,})['\"].*(?:password|pwd)", Pattern.CASE_INSENSITIVE),
            "Database Username with Password Context", 8),
        new DatabasePattern(
            Pattern.compile("(?:db_user|database_user|DB_USER)\\s*[:=]\\s*['\"]([^'\"\\s]+)['\"]", Pattern.CASE_INSENSITIVE),
            "Database Username Variable", 8),
            
        // Priority 7 - Complete database configs
        new DatabasePattern(
            Pattern.compile("database\\s*[:=]\\s*\\{[^}]*host\\s*[:=]\\s*['\"]([^'\"]+)['\"][^}]*\\}", Pattern.CASE_INSENSITIVE),
            "Database Configuration Object", 7),
        new DatabasePattern(
            Pattern.compile("sequelize\\s*\\([^)]*['\"]([^'\"]+)['\"][^)]*['\"]([^'\"]+)['\"][^)]*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            "Sequelize Configuration", 7),
            
        // Priority 6 - Database hosts and ports
        new DatabasePattern(
            Pattern.compile("(?:host|hostname|server)\\s*[:=]\\s*['\"]([^'\"]+\\.(?:com|net|org|io|local|localhost))['\"]", Pattern.CASE_INSENSITIVE),
            "Database Host", 6),
        new DatabasePattern(
            Pattern.compile("(?:port|db_port)\\s*[:=]\\s*['\"]?(\\d{4,5})['\"]?.*(?:mongo|mysql|postgres|redis)", Pattern.CASE_INSENSITIVE),
            "Database Port", 6),
            
        // Priority 5 - Database names
        new DatabasePattern(
            Pattern.compile("(?:database|db_name|schema)\\s*[:=]\\s*['\"]([^'\"\\s]+)['\"]", Pattern.CASE_INSENSITIVE),
            "Database Name", 5),
            
        // Priority 4 - Connection strings without credentials
        new DatabasePattern(
            Pattern.compile("(mongodb://[^\"'\\s@/]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "MongoDB Connection String", 4),
        new DatabasePattern(
            Pattern.compile("(mysql://[^\"'\\s@/]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "MySQL Connection String", 4),
        new DatabasePattern(
            Pattern.compile("(postgresql://[^\"'\\s@/]+(?:/[^\"'\\s]*)?)", Pattern.CASE_INSENSITIVE),
            "PostgreSQL Connection String", 4),
            
        // Priority 3 - Cloud database references  
        new DatabasePattern(
            Pattern.compile("([a-zA-Z0-9-]+\\.(?:rds\\.amazonaws\\.com|atlas\\.mongodb\\.com|database\\.azure\\.com))", Pattern.CASE_INSENSITIVE),
            "Cloud Database URL", 3),
            
        // Priority 2 - DB-related environment variables
        new DatabasePattern(
            Pattern.compile("process\\.env\\.([A-Z_]*(?:DB|DATABASE|MONGO|MYSQL|POSTGRES)[A-Z_]*)", Pattern.CASE_INSENSITIVE),
            "Database Environment Variable", 2),
            
        // Priority 1 - Generic database mentions
        new DatabasePattern(
            Pattern.compile("(?:connect|connection).*(?:mongodb|mysql|postgres|redis)", Pattern.CASE_INSENSITIVE),
            "Database Connection Reference", 1)
    };
    
    /**
     * Finds database credentials and connection information with priority ranking.
     */
    public static List<LeakInfo> findDatabaseCredentials(String jsContent, boolean onlyCritical) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        for (DatabasePattern dbPattern : DB_PATTERNS) {
            // For basic analysis, only include critical patterns (priority >= 7)
            if (onlyCritical && dbPattern.priority < 7) {
                continue;
            }
            
            Matcher matcher = dbPattern.pattern.matcher(jsContent);
            while (matcher.find()) {
                // Safe group extraction - use group(0) if no capturing groups
                String match;
                if (matcher.groupCount() > 0) {
                    match = matcher.group(1);
                } else {
                    match = matcher.group(0);
                }
                
                if (match != null && match.length() > 2) {
                    // Extract additional context for database credentials
                    String context = getMatchContext(jsContent, matcher.start(), matcher.end(), 100);
                    String enhancedInfo = enhanceDbInfo(match, context, dbPattern);
                    
                    LeakInfo leak = new LeakInfo(
                        dbPattern.description,
                        enhancedInfo,
                        context
                    );
                    leaks.add(leak);
                }
            }
        }
        
        // Sort by priority (highest first) and confidence
        leaks.sort((a, b) -> {
            double confidenceA = extractPriority(a.toString());
            double confidenceB = extractPriority(b.toString());
            return Double.compare(confidenceB, confidenceA);
        });
        
        return leaks;
    }
    
    /**
     * Enhances database information with extracted credentials and metadata.
     */
    private static String enhanceDbInfo(String match, String context, DatabasePattern pattern) {
        StringBuilder enhanced = new StringBuilder();
        enhanced.append("[Priority ").append(pattern.priority).append("] ");
        enhanced.append(match);
        
        // Try to extract additional credentials from context
        String username = extractUsername(context);
        String password = extractPassword(context);
        String database = extractDatabaseName(context);
        String host = extractHost(context);
        String port = extractPort(context);
        
        if (username != null) {
            enhanced.append(" | Username: ").append(username);
        }
        if (password != null) {
            enhanced.append(" | Password: ").append(password);
        }
        if (database != null) {
            enhanced.append(" | Database: ").append(database);
        }
        if (host != null) {
            enhanced.append(" | Host: ").append(host);
        }
        if (port != null) {
            enhanced.append(" | Port: ").append(port);
        }
        
        return enhanced.toString();
    }
    
    private static String extractUsername(String context) {
        Pattern userPattern = Pattern.compile("(?:user(?:name)?|uid)\\s*[:=]\\s*['\"]([^'\"\\s]{2,})['\"]", Pattern.CASE_INSENSITIVE);
        Matcher matcher = userPattern.matcher(context);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static String extractPassword(String context) {
        Pattern passPattern = Pattern.compile("(?:pass(?:word)?|pwd)\\s*[:=]\\s*['\"]([^'\"\\s]{3,})['\"]", Pattern.CASE_INSENSITIVE);
        Matcher matcher = passPattern.matcher(context);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static String extractDatabaseName(String context) {
        Pattern dbPattern = Pattern.compile("(?:database|db|schema)\\s*[:=]\\s*['\"]([^'\"\\s]+)['\"]", Pattern.CASE_INSENSITIVE);
        Matcher matcher = dbPattern.matcher(context);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static String extractHost(String context) {
        Pattern hostPattern = Pattern.compile("(?:host|server|hostname)\\s*[:=]\\s*['\"]([^'\"\\s]+)['\"]", Pattern.CASE_INSENSITIVE);
        Matcher matcher = hostPattern.matcher(context);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static String extractPort(String context) {
        Pattern portPattern = Pattern.compile("port\\s*[:=]\\s*['\"]?(\\d{2,5})['\"]?", Pattern.CASE_INSENSITIVE);
        Matcher matcher = portPattern.matcher(context);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private static String getMatchContext(String content, int start, int end, int contextLength) {
        int contextStart = Math.max(0, start - contextLength);
        int contextEnd = Math.min(content.length(), end + contextLength);
        return content.substring(contextStart, contextEnd);
    }
    
    private static double extractPriority(String text) {
        Pattern priorityPattern = Pattern.compile("Priority (\\d+)");
        Matcher matcher = priorityPattern.matcher(text);
        if (matcher.find()) {
            return Double.parseDouble(matcher.group(1)) * 10; // Convert to confidence scale
        }
        return 0.0;
    }
    
    /**
     * Database pattern holder class.
     */
    private static class DatabasePattern {
        final Pattern pattern;
        final String description;
        final int priority;
        
        DatabasePattern(Pattern pattern, String description, int priority) {
            this.pattern = pattern;
            this.description = description;
            this.priority = priority;
        }
    }
}