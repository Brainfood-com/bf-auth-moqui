package bf.auth;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;

import java.io.InputStream;
import org.moqui.Moqui;
import org.moqui.context.ExecutionContext;
import org.moqui.util.ObjectUtilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BfAuthKeycloakConfigResolver implements KeycloakConfigResolver {
    protected final static Logger logger = LoggerFactory.getLogger(BfAuthKeycloakConfigResolver.class);

    private InputStream getConfigStream() {
        ExecutionContext ec = Moqui.getExecutionContext();
        return ec.getResource().getLocationStream("component://bf-auth/config/bf-auth-moqui-keycloak.json");
    }

	@Override
    public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
        // This runs on every request, perhaps needs to be optimized to not read from disk all the time.
        //logger.info("resolve(" + request + ")");
        //InputStream is = getClass().getResourceAsStream("bf-auth-moqui-keycloak.json");
        //System.err.printf("keycloak json=%s", ObjectUtilities.getStreamText(is));
        //logger.info("config text=" + ObjectUtilities.getStreamText(getConfigStream()));
        return KeycloakDeploymentBuilder.build(getConfigStream());
    }
}
