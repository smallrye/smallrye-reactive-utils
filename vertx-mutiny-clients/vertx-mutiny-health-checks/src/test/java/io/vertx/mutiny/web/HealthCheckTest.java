package io.vertx.mutiny.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.smallrye.mutiny.Uni;
import io.vertx.ext.healthchecks.CheckResult;
import io.vertx.ext.healthchecks.Status;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.healthchecks.HealthCheckHandler;
import io.vertx.mutiny.ext.healthchecks.HealthChecks;
import io.vertx.mutiny.ext.web.Router;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;

public class HealthCheckTest {

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
    public void testHealthCheck() {
        HealthChecks hc = HealthChecks.create(vertx);
        hc.register("health", Uni.createFrom().item(Status::OK));

        CheckResult health = hc.checkStatusAndAwait("health");
        assertEquals(health.getId(), "health");
        assertTrue(health.getStatus().isOk());
    }

    @Test
    public void testHealthCheckWithVertxWeb() {
        HealthChecks hc = HealthChecks.create(vertx);
        HealthCheckHandler handler = HealthCheckHandler.createWithHealthChecks(hc);
        hc.register("test", Uni.createFrom().item(Status::OK));

        Router router = Router.router(vertx);
        router.get("/health*").handler(handler::handle);

        vertx.createHttpServer()
                .requestHandler(router::handle)
                .listenAndAwait(8085);

        WebClient webClient = WebClient.create(vertx);
        HttpResponse<Buffer> response1 = webClient.getAbs("http://localhost:8085/health").send().await()
                .indefinitely();

        assertEquals(response1.statusCode(), 200);
        assertEquals(response1.bodyAsJsonObject().getString("outcome"), "UP");

        HttpResponse<Buffer> response2 = webClient.getAbs("http://localhost:8085/health/test").send().await()
                .indefinitely();

        assertEquals(response2.statusCode(), 200);
        assertEquals(response2.bodyAsJsonObject().getString("outcome"), "UP");
    }

}
