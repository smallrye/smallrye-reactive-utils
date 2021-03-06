package io.vertx.mutiny.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.templ.rocker.RockerTemplateEngine;

public class RockerTemplateTest {

    private Vertx vertx;

    @Before
    public void setUp() {
        vertx = Vertx.vertx();
    }

    @After
    public void tearDown() {
        vertx.closeAndAwait();
    }

    @Test
    public void testTemplate() {
        RockerTemplateEngine engine = RockerTemplateEngine.create();

        Buffer buffer = engine.render(new JsonObject().put("foo", "hello"), "templates/MyTemplate.rocker.html")
                .await().indefinitely();
        assertThat(buffer.toString()).contains("hello").doesNotContain("foo");
    }

}
