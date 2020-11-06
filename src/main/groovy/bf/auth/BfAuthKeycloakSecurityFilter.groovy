
package bf.auth;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.AuthorizationContext;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.moqui.Moqui;
import org.moqui.context.ExecutionContext;
import org.moqui.util.ObjectUtilities;


import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
/*



import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
*/

public class BfAuthKeycloakSecurityFilter implements Filter {
    protected final static Logger logger = LoggerFactory.getLogger(BfAuthKeycloakSecurityFilter.class);

    @Override
    public void init(FilterConfig config) throws ServletException {
    }

    private static void appendKeycloakSecurityContext(StringBuilder sb, KeycloakSecurityContext ksc) {
        sb.append("KeycloakSecurityContext(");
        sb.append("realm=").append(ksc.getRealm()).append(";");
        sb.append(")");
    }

    private static void appendIDToken(StringBuilder sb, KeycloakSecurityContext ksc) {
        IDToken idToken = ksc.getIdToken();
        if (idToken == null) {
            return
        }
        sb.append("IDToken(");
        sb.append("id=").append(idToken.getId()).append(";");
        sb.append("subject=").append(idToken.getSubject()).append(";");
        sb.append("authTime=").append(idToken.getAuthTime()).append(";");
        sb.append("name=").append(idToken.getName()).append(";");
        sb.append("givenName=").append(idToken.getGivenName()).append(";");
        sb.append("familyName=").append(idToken.getFamilyName()).append(";");
        sb.append("middleName=").append(idToken.getMiddleName()).append(";");
        sb.append("nickName=").append(idToken.getNickName()).append(";");
        sb.append("preferredUsername=").append(idToken.getPreferredUsername()).append(";");
        sb.append("profile=").append(idToken.getProfile()).append(";");
        sb.append("picture=").append(idToken.getPicture()).append(";");
        sb.append("website=").append(idToken.getWebsite()).append(";");
        sb.append("email=").append(idToken.getEmail()).append(";");
        sb.append("emailVerified=").append(idToken.getEmailVerified()).append(";");
        sb.append("gender=").append(idToken.getGender()).append(";");
        sb.append("birthdate=").append(idToken.getBirthdate()).append(";");
        sb.append("zoneinfo=").append(idToken.getZoneinfo()).append(";");
        sb.append("locale=").append(idToken.getLocale()).append(";");
        sb.append("phoneNumber=").append(idToken.getPhoneNumber()).append(";");
        sb.append("phoneNumberVerified=").append(idToken.getPhoneNumberVerified()).append(";");
        //
        sb.append("address=").append(idToken.getAddress()).append(";");
        sb.append("updatedAt=").append(idToken.getUpdatedAt()).append(";");
        sb.append("claimsLocales=").append(idToken.getClaimsLocales()).append(";");
        sb.append("acr=").append(idToken.getAcr()).append(";");
        //
        sb.append("category=").append(idToken.getCategory()).append(";");
        sb.append(")");
    }

    private static void appendAccessToken(StringBuilder sb, KeycloakSecurityContext ksc) {
        AccessToken accessToken = ksc.getToken();
        sb.append("AccessToken(");
        sb.append("roles=").append(accessToken.getRealmAccess().getRoles()).append(";");
        sb.append("resourceAccess=").append(accessToken.getResourceAccess()).append(";");
        sb.append("isVerifyCaller=").append(accessToken.isVerifyCaller()).append(";");
        sb.append("allowedOrigins=").append(accessToken.getAllowedOrigins()).append(";");
        sb.append("authorization=").append(accessToken.getAuthorization()).append(";");
        sb.append("scope=").append(accessToken.getScope()).append(";");
               Map<String, AccessToken.Access> resourceAccess = accessToken.getResourceAccess()
               for (Map.Entry<String, AccessToken.Access> entry: resourceAccess.entrySet()) {
                       sb.append("Resource(").append(entry.getKey()).append(")");
                       appendAccessTokenAccess(sb, entry.getValue());
                       sb.append(";");
               }
        sb.append("otherClaims=").append(accessToken.getOtherClaims()).append(";");
        appendAccessTokenAccess(sb.append("Realm"), accessToken.getRealmAccess());
        sb.append(";");
        appendAccessTokenAuthorization(sb, accessToken.getAuthorization());
        sb.append(";");
        appendAccessTokenCertConf(sb, accessToken.getCertConf());
        sb.append(")");
    }

    private static void appendAccessTokenAccess(StringBuilder sb, AccessToken.Access access) {
        sb.append("Access(");
        if (access != null) {
            sb.append("roles=").append(access.getRoles()).append(";");
            sb.append("verifyCaller=").append(access.getVerifyCaller()).append(";");
        }
        sb.append(")");
    }

    private static void appendAccessTokenAuthorization(StringBuilder sb, AccessToken.Authorization authorization) {
        sb.append("Authorization(");
        if (authorization != null) {
            sb.append("permissions=").append(authorization.getPermissions()).append(";");
        }
        sb.append(")");
    }

    private static void appendAccessTokenCertConf(StringBuilder sb, AccessToken.CertConf certConf) {
        sb.append("CertConf(");
        if (certConf != null) {
            sb.append("certThumbprint=").append(certConf.getCertThumbprint()).append(";");
        }
        sb.append(")");
    }

    public static void showKeycloakSecurityContext(KeycloakSecurityContext ksc) {
        if (ksc == null) {
            return;
        }
        IDToken idToken = ksc.getIdToken();
        AuthorizationContext authContext = ksc.getAuthorizationContext();
        StringBuilder sb = new StringBuilder();
        // not release yet: sb.append("authTime=").append(idToken.getAuth_time()).append(";");
        appendKeycloakSecurityContext(sb, ksc);
        sb.append(", ");
        appendIDToken(sb, ksc);
        sb.append(", ");
        appendAccessToken(sb, ksc);

        logger.info(" sb=" + sb);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Can also look at the session if needed
        KeycloakSecurityContext ksc = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
        logger.info("doFilter(" + ksc + ")");
        showKeycloakSecurityContext(ksc);
        //importKeycloakSecurityContext(ksc);
        String username = null;
        if (ksc != null) {
            ExecutionContext ec = Moqui.getExecutionContext();
            //ec.user.pushUser('keycloak-api');
            try {
                // FIXME: This is bad, I don't know how to force a login without a password.
                ec.user.loginUser('keycloak-api', 'moqui');
                Map<String, Object> result = ec.service.sync().name("bf.auth.KeycloakServices.import#KeycloakUser").parameters([ksc: ksc]).call();
                logger.info('result=' + result)
                username = result?.userAccount?.username
                request.setAttribute('moqui.request.authenticated', 'true')
            } finally {
                //ec.user.popUser();
            }
        }
        shiroRunAs(username, request.getSession(), { chain.doFilter(request, response) });
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

        /*
         * Party.ExternalId=idToken.getSubject()
         * Person.firstName=idToken.getGivenName()
         * Person.middleName=idToken.getMiddleName()
         * Person.lastName=idToken.getFamilyName()
         * Person.gender=idToken.getGender()
         * PartyContactMech.contactMechTypeId=EMAIL_ADDRESS
         * PartyContactMech.infoString=idToken.getEmail()
         * PartyContactMech.contactMechTypeId=PHONE_NUMBER
         * PartyContactMech.infoString=idToken.getPhoneNumber()
         * UserLogin=idToken.getPreferredUsername()
         *
         */


    @Override
    public void destroy() {
    }
}
