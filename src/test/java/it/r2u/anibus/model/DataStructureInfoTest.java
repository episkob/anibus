package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class DataStructureInfoTest {

    @Test
    void mergeOptionalMarksFieldsPresentInOnlyOneVariant() {
        DataStructureInfo a = new DataStructureInfo(
                "UserReq",
                DataStructureInfo.DataType.REQUEST_PAYLOAD,
                Map.of("id", "number", "email", "string"),
                List.of("validate"),
                "ctxA",
                false,
                Set.of("email"));

        DataStructureInfo b = new DataStructureInfo(
                "UserReqAlt",
                DataStructureInfo.DataType.REQUEST_PAYLOAD,
                Map.of("id", "number", "phone", "string"),
                List.of("validate"),
                "ctxB",
                false,
                Set.of());

        DataStructureInfo merged = DataStructureInfo.mergeOptional(a, b);

        assertEquals("UserReq", merged.getName());
        assertEquals(3, merged.getProperties().size());
        assertTrue(merged.getProperties().containsKey("phone"));
        assertTrue(merged.isOptional("phone"));
        assertTrue(merged.isOptional("email"));
        assertTrue(merged.toString().contains("optional"));
    }
}