
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
import org.moqui.Moqui;
import org.moqui.context.ExecutionContext;
import org.moqui.util.ObjectUtilities;


import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.subject.Subject;
/*



import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
*/

public class AuthKeycloakUtil implements Filter {
    protected final static Logger logger = LoggerFactory.getLogger(BfAuthKeycloakSecurityFilter.class);

	@Override
    public void init(FilterConfig config) throws ServletException {
    }

    public static void showKeycloakSecurityContext(KeycloakSecurityContext kcContext) {
        if (kcContext == null) {
            return;
        }
        IDToken idToken = kcContext.getIdToken();
        AuthorizationContext authContext = kcContext.getAuthorizationContext();
        StringBuilder sb = new StringBuilder();
        // not release yet: sb.append("authTime=").append(idToken.getAuth_time()).append(";");
        sb.append("KeycloakSecurityContext(");
        sb.append("realm=").append(kcContext.getRealm()).append(";");
        sb.append("), IDToken(");
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
        sb.append("), AccessToken(");
        AccessToken accessToken = kcContext.getToken();
        sb.append("roles=").append(accessToken.getRealmAccess().getRoles()).append(";");
        sb.append("resourceAccess=").append(accessToken.getResourceAccess()).append(";");
        sb.append("isVerifyCaller=").append(accessToken.isVerifyCaller()).append(";");
        sb.append("allowedOrigins=").append(accessToken.getAllowedOrigins()).append(";");
        sb.append("authorization=").append(accessToken.getAuthorization()).append(";");
        sb.append("scope=").append(accessToken.getScope()).append(";");
        sb.append(")");
        logger.info(" sb=" + sb);
    }

	@Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Can also look at the session if needed
        KeycloakSecurityContext kcContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
        logger.info("doFilter(" + kcContext + ")");
        showKeycloakSecurityContext(kcContext);
        importKeycloakSecurityContext(kcContext);
        chain.doFilter(request, response);
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

    public static Map<String, Object> attachKeycloakSecurityContext(ExecutionContext ec, KeycloakSecurityContext kcContext, String partyId) {
        if (kcContext == null) {
            return;
        }
        IDToken idToken = kcContext.getIdToken();
        Map<String, Object> svcContext = [
            //authUsername: 'alyvr',
            //authPassword: 'moqui',
            partyId: partyId,
            providers: [
                [
                    name: 'keycloak',
                    //token: ??,
                    profile: [
                        id: idToken.getSubject(),
                        displayName: idToken.getName(),
                        gender: idToken.getGender(),
                        name: [
                            givenName: idToken.getGivenName(),
                            middleName: idToken.getMiddleName(),
                            familyName: idToken.getFamilyName(),
                        ],
                        emails: [
                            [
                                value: idToken.getEmail(),
                            ],
                        ],
                    ],
                ],
/*
                [
                    name: 'facebook',
                    token: ??,
                    profile: [
                        id: idToken.getSubject(),
                        emails: [],
                    ],
                ],
*/
            ],
        ];
        logger.info('about to call createOrAttachAccount: ' + svcContext);
		ec.user.pushUser('bf-auth-demo-api');
        try {
/*
			UsernamePasswordToken token = new UsernamePasswordToken('alyvr', 'moqui');
			UsernamePasswordToken token = new UsernamePasswordToken('bf-auth-demo-api', 'moqui');
			Subject loginSubject = ec.getEcfi().getSecurityManager().createSubject(new DefaultSubjectContext());
			loginSubject.login(token);
*/
			//def user = ec.find('UserAccount').condition('userId', '_NA_');
            //ec.user.loginUser('bf-auth-demo-api', 'moqui');
			//ec.user.internalLoginUser('_NA_', false);
            return ec.service.sync().name("bf.auth.AuthServices.create#Account").parameters(svcContext).call();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            ec.user.popUser();
        }
    }

	@Override
    public void destroy() {
    }
}

