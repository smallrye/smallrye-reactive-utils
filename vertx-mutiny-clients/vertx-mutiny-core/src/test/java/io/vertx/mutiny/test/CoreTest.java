package io.vertx.mutiny.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import io.smallrye.mutiny.Uni;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.impl.Utils;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.eventbus.EventBus;
import io.vertx.mutiny.core.eventbus.Message;
import io.vertx.mutiny.core.file.AsyncFile;
import io.vertx.mutiny.core.http.*;
import io.vertx.test.core.TestUtils;
import io.vertx.test.core.VertxTestBase;

public class CoreTest extends VertxTestBase {

    private static final String DEFAULT_FILE_PERMS = "rw-r--r--";
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    private Vertx vertx;
    private String pathSep;
    private String testDir;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        vertx = new Vertx(super.vertx);
        java.nio.file.FileSystem fs = FileSystems.getDefault();
        pathSep = fs.getSeparator();
        File ftestDir = testFolder.newFolder();
        testDir = ftestDir.toString();
    }

    @Test
    public void testAsyncFile() throws Exception {
        String fileName = "some-file.dat";
        int chunkSize = 1000;
        int chunks = 10;
        byte[] expected = TestUtils.randomAlphaString(chunkSize * chunks).getBytes();
        createFile(fileName, expected);
        vertx.fileSystem().open(testDir + pathSep + fileName, new OpenOptions())
                .subscribeAsCompletionStage().whenComplete((file, err) -> {
                    assertNull(err);
                    subscribe(expected, file, 3);
                });
        await();
    }

    @Test
    public void testAsyncFileBlocking() throws Exception {
        String fileName = "some-file.dat";
        int chunkSize = 1000;
        int chunks = 10;
        byte[] expected = TestUtils.randomAlphaString(chunkSize * chunks).getBytes();
        createFile(fileName, expected);
        Buffer buffer = Buffer.buffer();
        AsyncFile asyncFile = vertx.fileSystem().openAndAwait(testDir + pathSep + fileName, new OpenOptions());
        asyncFile.toBlockingStream().forEach(b -> buffer.appendBuffer(b.getDelegate()));
        assertEquals(Buffer.buffer(expected), buffer);
    }

    @Test
    public void testAndWaitMethod() {
        EventBus eventBus = vertx.eventBus();
        eventBus.consumer("my-address").handler(m -> m.getDelegate().reply(m.body() + " world"));
        Message<Object> message = eventBus.requestAndAwait("my-address", "hello");
        assertEquals("hello world", message.body());
    }

    @Test
    public void testWebSocket() {
        waitFor(2);
        AtomicLong serverReceived = new AtomicLong();
        // Set a 2 seconds timeout to force a TCP connection close
        vertx.createHttpServer(new HttpServerOptions().setIdleTimeout(2)).webSocketHandler(ws -> {
            ws.toMulti()
                    .subscribe().with(msg -> {
                        serverReceived.incrementAndGet();
                        ws.writeTextMessageAndForget("pong");
                        complete();
                    }, (Consumer<Throwable>) this::fail);
        }).listenAndAwait(8080, "localhost");

        HttpClient client = vertx.createHttpClient();
        AtomicLong clientReceived = new AtomicLong();
        client.webSocket(8080, "localhost", "/")
                .onItem().call(ws -> ws.writeTextMessage("ping"))
                .onItem().transformToMulti(WebSocket::toMulti)
                .subscribe().with(
                        msg -> {
                            clientReceived.incrementAndGet();
                            complete();
                        }, (Consumer<Throwable>) this::fail);
        await();
        assertEquals(1, serverReceived.get());
        assertEquals(1, clientReceived.get());
    }

    @Test
    public void testTimer() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        vertx.setTimer(10, x -> latch.countDown());

        assertTrue(latch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void testPeriodicTimer() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(5);
        vertx.setPeriodic(10, x -> latch.countDown());

        assertTrue(latch.await(1, TimeUnit.SECONDS));
    }

    private void subscribe(byte[] expected, AsyncFile file, int times) {
        file.setReadPos(0);
        Buffer actual = Buffer.buffer();
        file.toMulti()
                .onItem().transform(io.vertx.mutiny.core.buffer.Buffer::getDelegate)
                .onItem().invoke(actual::appendBuffer)
                .onItem().ignoreAsUni()
                .subscribeAsCompletionStage()
                .exceptionally(t -> {
                    fail(t);
                    return null;
                })
                .whenComplete((x, e) -> {
                    assertEquals(Buffer.buffer(expected), actual);
                    if (times > 0) {
                        subscribe(expected, file, times - 1);
                    } else {
                        testComplete();
                    }
                });
    }

    private void createFile(String fileName, byte[] bytes) throws Exception {
        File file = new File(testDir, fileName);
        Path path = Paths.get(file.getCanonicalPath());
        Files.write(path, bytes);
        setDefaultPerms(path);
    }

    private void setDefaultPerms(Path path) {
        if (!Utils.isWindows()) {
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(DEFAULT_FILE_PERMS));
            } catch (IOException e) {
                throw new RuntimeException(e.getMessage());
            }
        }
    }

    @Test
    public void testFollowRedirect() {
        HttpServerOptions options = new HttpServerOptions().setPort(8081).setHost("localhost");
        AtomicInteger redirects = new AtomicInteger();
        HttpServer server = vertx.createHttpServer(options)
                .requestHandler(req -> {
                    redirects.incrementAndGet();
                    req.response().setStatusCode(301)
                            .putHeader(HttpHeaders.LOCATION, "http://localhost:" + 8082 + "/whatever").endAndForget();
                });
        server.listenAndAwait();

        HttpServer server2 = vertx.createHttpServer(options.setPort(8082));
        server2.requestHandler(req -> {
            assertEquals(1, redirects.get());
            assertEquals("http://localhost:" + 8082 + "/custom", req.absoluteURI());
            req.response().endAndForget();
            complete();
        });
        server2.listenAndAwait();

        HttpClient client = vertx.createHttpClient();
        client.redirectHandler(resp -> Uni.createFrom().emitter(e -> vertx.setTimer(25,
                id -> e.complete(
                        new RequestOptions().setAbsoluteURI("http://localhost:" + 8082 + "/custom")))));

        HttpClientResponse response = client.request(new RequestOptions().setHost("localhost").setPort(8081))
                .onItem().transformToUni(req -> {
                    req.setFollowRedirects(true);
                    return req.send();
                })
                .await().indefinitely();
        assertEquals("http://localhost:" + 8082 + "/custom", response.request().absoluteURI());

    }
}
