import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field

import org.apache.commons.lang3.RandomStringUtils
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityCondition
import org.moqui.entity.EntityFind
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.moqui.util.ObjectUtilities
import org.slf4j.Logger
import org.slf4j.LoggerFactory


import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

@Field Logger logger = LoggerFactory.getLogger(getClass().getName())
@Field Timestamp now = context.ec.user.nowTimestamp

private static Map<String, String> keycloakGroupMap = [
    '/super-admin': 'ADMIN',
]

private void updateIf(String serviceName, EntityValue entity, Map<String, Object> fields) {
    Map<String, Object> serviceContext = [:]
    for (Map.Entry<String, Object> fieldsEntry: fields.entrySet()) {
        if (entity[fieldsEntry.getKey()] != fieldsEntry.getValue()) {
            serviceContext[fieldsEntry.getKey()] = fieldsEntry.getValue()
        }
    }
    if (serviceContext.isEmpty()) {
        return
    }
    ec.service.sync().name(serviceName).parameters(serviceContext).call()
}

public Map<String, Object> importKeycloakUser() {
	// TODO: Only update when a new login is detected, not on each request
    ExecutionContext ec = context.ec
    KeycloakSecurityContext ksc = context.ksc
    if (ksc == null) return [:]
    //return [:]

    IDToken idToken = ksc.getIdToken()
    String keycloakUserId = idToken.getSubject()

    EntityValue userAccount = ec.entity.find('UserAccount').condition(['usernamne': keycloakUserId, isAuthAccount: 'Y']).one()
dToken.getAuthTime()

    if (userAccount == null) {
        userAccount = ec.entity.makeValue('UserAccount').setAll([
            username: keycloakUserId,
            isAuthAccount: 'Y',
        ]).setSequencedIdPrimary().create()
    }
    String partyId = userAccount.partyId
    EntityValue person = null
    if (partyId == null) {
        partyId = ec.entity.makeValue('Party').setAll([
            partyTypeEnumId: 'PtyPerson',
        ]).setSequencedIdPrimary().createOrUpdate().partyId
        person = ec.entity.makeValue('Person').setAll([
            partyId: partyId,
        ])
        userAccount.partyId = partyId
        userAccount.update()
        logger.info('created partyId:' + partyId)
    } else {
        person = ec.entity.find('Person').condition('partyId', partyId).one()
    }
    updateIf('update#Person', person, [
        firstName: idToken.getGivenName(),
        middleName: idToken.getMiddleName(),
        lastName: idToken.getFamilyName(),
        gender: idToken.getGender(),
    ])

    // Map emails
    List<String> emails = [idToken.getEmail()]
	Map<String, String> emailToCMId = [:]
	for (String email: emails) {
		emailToCMId[email] = null
	}
    EntityList partyCMs = ec.entity.find('mantle.party.contact.PartyContactMechInfo').condition([
        partyd: partyId,
        contactMechTypeEnumId: 'CmtEmailAddress',
		contactMechPurposeId: 'BF_AUTH',
    ]).conditionDate('fromDate', 'thruDate', now).list()

    for (EntityValue partyCM: partyCMs) {
        switch (partyCM.contactMechTypeEnumId) {
            case 'CmtEmailAddress':
				if (emailToCMId[partyCM.infoString] == null) {
					emailToCMId[partyCM.infoString] = partyCM.contactMechId
				} else if (emailToCMId[partyCM.infoString] != partyCM.contactMechId) {
					ec.entity.find('mantle.party.contact.PartyContactMech').condition([
						contactMechId: partyCM.contactMechId,
						partyId: partyCM.partyId,
						contactMechPurposeId: 'BF_AUTH',
						fromDate: partyCM.fromDate,
					]).updateAll([thruDate: now])
				}
                break
        }
    }
	for (Map.Entry<String, String> emailEntry: emailToCMId.entrySet()) {
		if (emailEntry.value == null) {
			emailEntry.value = ec.entity.makeValue('mantle.party.contact.ContactMech').setAll([
				contactMechTypeEnumId: 'CmtEmailAddress',
        	]).setSequencedIdPrimary().createOrUpdate().contactMechId

			ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
				partyId: partyId,
				contactMechId: emailEntry.value,
				contactMechPurposeId: 'BF_AUTH',
				fromDate: now,
			]).createOrUpdate()
		}
	}
    // Map groups
    List<String> groups = ksc.getToken().getOtherClaims()['groups']
    for (Map.Entry<String, String> keycloakGroupMapEntry: keycloakGroupMap.entrySet()) {
        String keycloakGroupName = keycloakGroupMapEntry.getKey()
        String moquiGroupName = keycloakGroupMapEntry.getValue()
        if (groups != null && groups.contains(keycloakGroupName)) {
            EntityList accountGroups = ec.entity.find('UserGroupMember').condition([
                userGroupId: moquiGroupName,
                userId: userAccount.userId,
            ]).conditionDate('fromDate', 'thruDate', now).list()
            if (accountGroups.isEmpty()) {
                ec.entity.makeValue('UserGroupMember').setAll([
                    userGroupId: moquiGroupName,
                    userId: userAccount.userId,
                    fromDate: now,
                ]).create()
            }
        } else {
            ec.entity.find('UserGroupMember').condition([
                userGroupId: moquiGroupName,
                userId: userAccount.userId,
            ]).updateAll([thruDate: now])
        }

    }

	return [
		userAccount: userAccount,
	]
}
