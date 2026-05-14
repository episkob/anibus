package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import it.r2u.anibus.model.EndpointInfo;

class HarPostmanParserTest {

    @Test
    void detectsHarFormat() {
        String har = """
            {"log":{"version":"1.2","entries":[
              {"request":{"method":"GET","url":"https://api.example.com/v1/users?limit=10"}},
              {"request":{"method":"POST","url":"https://api.example.com/v1/login"}}
            ]}}""";
        HarPostmanParser.ParseResult r = HarPostmanParser.parse(har);
        assertEquals(HarPostmanParser.Format.HAR, r.format());
        assertEquals(2, r.endpoints().size());
        EndpointInfo first = r.endpoints().get(0);
        assertEquals("GET", first.getHttpMethod());
        assertEquals("https://api.example.com", first.getBaseUrl());
        assertEquals("/v1/users", first.getPath());
        assertTrue(first.getParameters().contains("limit"));
    }

    @Test
    void detectsPostmanRawUrlObject() {
        String postman = """
            {"info":{"_postman_id":"abc","name":"Test","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
             "item":[
               {"name":"List users","request":{"method":"GET","header":[],"url":{"raw":"https://api.example.com/users","host":["api","example","com"],"path":["users"]}}},
               {"name":"Create","request":{"method":"POST","url":{"raw":"https://api.example.com/users"}}}
             ]}""";
        HarPostmanParser.ParseResult r = HarPostmanParser.parse(postman);
        assertEquals(HarPostmanParser.Format.POSTMAN, r.format());
        assertEquals(2, r.endpoints().size());
        assertEquals("GET", r.endpoints().get(0).getHttpMethod());
        assertEquals("POST", r.endpoints().get(1).getHttpMethod());
    }

    @Test
    void unknownFormatReturnsEmpty() {
        HarPostmanParser.ParseResult r = HarPostmanParser.parse("{\"foo\":\"bar\"}");
        assertEquals(HarPostmanParser.Format.UNKNOWN, r.format());
        assertTrue(r.endpoints().isEmpty());
    }

    @Test
    void nullAndBlankAreSafe() {
        assertEquals(HarPostmanParser.Format.UNKNOWN, HarPostmanParser.parse(null).format());
        assertEquals(HarPostmanParser.Format.UNKNOWN, HarPostmanParser.parse("").format());
        assertEquals(HarPostmanParser.Format.UNKNOWN, HarPostmanParser.parse("   ").format());
    }

    @Test
    void dedupesIdenticalEntries() {
        String har = """
            {"log":{"entries":[
              {"request":{"method":"GET","url":"https://api/x"}},
              {"request":{"method":"GET","url":"https://api/x"}}
            ]}}""";
        HarPostmanParser.ParseResult r = HarPostmanParser.parse(har);
        assertEquals(1, r.endpoints().size());
    }
}
