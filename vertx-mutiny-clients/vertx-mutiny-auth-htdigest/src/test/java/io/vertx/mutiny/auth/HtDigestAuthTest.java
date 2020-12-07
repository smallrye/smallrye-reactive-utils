package io.vertx.mutiny.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.vertx.ext.auth.htdigest.HtdigestCredentials;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.ext.auth.User;
import io.vertx.mutiny.ext.auth.htdigest.HtdigestAuth;

public class HtDigestAuthTest {

    private Vertx vertx;
    private HtdigestAuth authProvider;

    @Before
    public void setup() {
        vertx = Vertx.vertx();
        authProvider = HtdigestAuth.create(vertx);
    }

    @After
    public void tearDown() {
        vertx.closeAndAwait();
    }

    @Test
    public void testValidDigestWithQOP() {
        HtdigestCredentials authInfo = new HtdigestCredentials()
                .setMethod("GET")
                .setUsername("Mufasa")
                .setRealm("testrealm@host.com")
                .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
                .setUri("/dir/index.html")
                .setQop("auth")
                .setNc("00000001")
                .setCnonce("0a4f113b")
                .setResponse("6629fae49393a05397450978507c4ef1");

        User user = authProvider.authenticate(authInfo).await().indefinitely();
        assertNotNull(user);
        assertEquals("Mufasa", user.principal().getString("username"));
    }

    @Test
    public void testValidDigestWithoutQOP() {
        HtdigestCredentials authInfo = new HtdigestCredentials()
                .setMethod("GET")
                .setUsername("Mufasa")
                .setRealm("testrealm@host.com")
                .setNonce("dcd98b7102dd2f0e8b11d0f600bfb0c093")
                .setUri("/dir/index.html")
                .setNc("00000001")
                .setCnonce("0a4f113b")
                .setResponse("670fd8c2df070c60b045671b8b24ff02");

        User user = authProvider.authenticate(authInfo).await().indefinitely();
        assertNotNull(user);
        assertNotNull(user);
        assertEquals("Mufasa", user.principal().getString("username"));
    }

}
