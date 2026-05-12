package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class DatabaseSchemaInfoTest {

    @Test
    void toStringContainsTypeTableAndConfidence() {
        DatabaseSchemaInfo info = new DatabaseSchemaInfo(
                "orders",
                DatabaseSchemaInfo.DatabaseType.SQL,
                Map.of("id", "number", "total", "number"),
                List.of("orders.user_id -> users.id"),
                List.of("idx_orders_user_id"),
                "ctx",
                0.83);

        String text = info.toString();
        assertTrue(text.contains("SQL Table: orders"));
        assertTrue(text.contains("2 columns"));
        assertTrue(text.contains("83% confidence"));
    }
}