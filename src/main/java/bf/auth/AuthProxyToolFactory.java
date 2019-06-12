package bf.auth;

import java.security.GeneralSecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.moqui.context.ExecutionContextFactory;
import org.moqui.context.ToolFactory;

public class AuthProxyToolFactory implements ToolFactory<AuthProxyTool> {
    private static final Logger logger = LoggerFactory.getLogger(AuthProxyToolFactory.class);
    private AuthProxyTool authProxyTool;

    @Override
    public void init(ExecutionContextFactory ecf) {
        try {
            authProxyTool = new AuthProxyTool(ecf);
        } catch (GeneralSecurityException e) {
            throw (UnsupportedOperationException) new UnsupportedOperationException(e.getMessage()).initCause(e);
        }
    }

    @Override
    public AuthProxyTool getInstance(Object... parameters) {
        return authProxyTool;
    }
}
