package bf.auth;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.util.Base64;
import java.util.concurrent.Callable;

import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;

import org.moqui.entity.EntityValue;
import org.moqui.context.ExecutionContextFactory;
import org.moqui.context.ToolFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// FIXME: Eventually allow the public/private keys to be in the config
// TODO: Allow for key rotation
public class AuthProxyTool {
    private static final Logger logger = LoggerFactory.getLogger(AuthProxyTool.class);
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final Base64.Encoder encoder = Base64.getEncoder();

    private final ExecutionContextFactory ecf;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public AuthProxyTool(ExecutionContextFactory ecf) throws GeneralSecurityException {
        this.ecf = ecf;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
    }

    public String buildAuthorizationHeader(EntityValue userAccount) throws GeneralSecurityException {
        String token = userAccount.getString("username");
        byte[] tokenBytes = decoder.decode(token);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(token.getBytes());
        return "AuthToken " + encoder.encodeToString(encryptedBytes);
    }

    public String decodeAuthorization(String authorization) throws GeneralSecurityException {
        if (authorization != null && authorization.startsWith("AuthToken ")) {
            String authToken = authorization.substring("AuthToken ".length());
            byte[] authBytes = decoder.decode(authToken);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(authBytes);
            String username = new String(decryptedBytes);
            return username;
        }
        return null;
    }

    public static void checkSetAttribute(HttpSession session, String name, Object value) {
        if (session != null && value != null) {
            session.setAttribute(name, value);
        }
    }

    public static void shiroSetUser(Object principal, HttpSession session) throws IOException, ServletException {
        if (principal != null) {
            session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, new SimplePrincipalCollection(principal, "moquiRealm"));
            session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, true);
        } else {
            session.setAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY, null);
            session.setAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, null);
        }
    }

    // This only works when called *before* moqui filter or servlet; that
    // implies an impedance mismatch, as moqui fetches the shiro user once,
    // and never rechecks.
    public static void shiroRunAs(Object principal, HttpSession session, ServletCallable callable) throws IOException, ServletException {
        Object origPrincipals = session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
        Object origAuthenticated = session.getAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);
        try {
            shiroSetUser(principal, session);
            callable.call();
        } finally {
            checkSetAttribute(session, DefaultSubjectContext.PRINCIPALS_SESSION_KEY, origPrincipals);
            checkSetAttribute(session, DefaultSubjectContext.AUTHENTICATED_SESSION_KEY, origAuthenticated);
        }
    }

    @FunctionalInterface
    public interface ServletCallable {
        void call() throws IOException, ServletException;
    }
}
