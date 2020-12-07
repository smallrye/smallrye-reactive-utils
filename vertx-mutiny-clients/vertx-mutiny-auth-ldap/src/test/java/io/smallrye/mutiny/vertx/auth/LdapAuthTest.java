package io.smallrye.mutiny.vertx.auth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CompletionException;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.CreateLdapServerRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.ldap.LdapAuthenticationOptions;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.ext.auth.User;
import io.vertx.mutiny.ext.auth.ldap.LdapAuthentication;

@CreateDS(name = "myDS", partitions = { @CreatePartition(name = "test", suffix = "dc=myorg,dc=com") })
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP", address = "localhost") })
@ApplyLdifFiles({ "ldap.ldif" })
public class LdapAuthTest {

    private Vertx vertx;

    @ClassRule
    public static CreateLdapServerRule serverRule = new CreateLdapServerRule();
    private LdapAuthentication provider;

    @Before
    public void setUp() {
        vertx = Vertx.vertx();
        LdapAuthenticationOptions ldapOptions = new LdapAuthenticationOptions()
                .setUrl("ldap://localhost:" + serverRule.getLdapServer().getPort())
                .setAuthenticationQuery("uid={0},ou=Users,dc=myorg,dc=com");

        provider = LdapAuthentication.create(vertx, ldapOptions);
    }

    @After
    public void tearDown() {
        vertx.closeAndAwait();
    }

    @Test
    public void testSimpleAuthenticate() {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
        User user = provider.authenticate(credentials).await().indefinitely();
        assertNotNull(user);
    }

    @Test
    public void testSimpleAuthenticateFailWrongPassword() {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "wrongpassword");
        try {
            provider.authenticate(credentials).await().indefinitely();
        } catch (CompletionException e) {
            assertTrue(e.getMessage().contains("INVALID_CREDENTIALS"));
        }
    }

    @Test
    public void testSimpleAuthenticateFailWrongUser() {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("frank", "sausages");
        try {
            provider.authenticate(credentials).await().indefinitely();
        } catch (CompletionException e) {
            assertTrue(e.getMessage().contains("INVALID_CREDENTIALS"));
        }
    }
}
