package com.github.rmannibucau.oauth2;

import com.github.rmannibucau.oauth2.backend.entity.ClientEntity;
import lombok.Getter;
import org.apache.openejb.testing.Application;
import org.apache.openejb.testing.ContainerProperties;
import org.apache.openejb.testing.RandomPort;

import javax.annotation.Resource;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Observes;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;
import javax.transaction.UserTransaction;
import java.io.File;
import java.net.URL;

import static org.apache.openejb.loader.JarLocation.jarLocation;

@Getter
@Application
@ContainerProperties(
    @ContainerProperties.Property(name = "openejb.jul.forceReload", value = "true")
)
public class App {
    public static final String CLIENT_ID = "client";
    public static final String CLIENT_SECRET = "secret";

    @RandomPort("http")
    private URL base;

@Dependent // test doesnt have a beans.xml
private static final class Init {
    @PersistenceContext
    private EntityManager em;

    @Resource
    private UserTransaction ut;

    void init(@Observes @Initialized(ApplicationScoped.class) final Object start) throws Throwable {
        addClient();
        setJaas();
    }

    private void setJaas() {
        System.setProperty("java.security.auth.login.config", new File(jarLocation(App.class), "oauth2.jaas").getAbsolutePath());
    }

    private void addClient() throws NotSupportedException, SystemException, HeuristicMixedException, HeuristicRollbackException, RollbackException {
        final ClientEntity entity = new ClientEntity();
        entity.setId(CLIENT_ID);
        entity.setSecret(CLIENT_SECRET);
        entity.setConfidential(true);
        ut.begin();
        em.persist(entity);
        ut.commit();
    }
}
}
