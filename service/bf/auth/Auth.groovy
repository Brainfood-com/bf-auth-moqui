/*
 * This software is in the public domain under CC0 1.0 Universal plus a
 * Grant of Patent License.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software (see the LICENSE.md file). If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

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

import java.util.Base64
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import bf.auth.AuthProxyTool

@Field Logger logger = LoggerFactory.getLogger(getClass().getName())
@Field Timestamp now = context.ec.user.nowTimestamp

public Map<String, Object> connect() {
    logger.info('connect')
    ExecutionContext ec = context.ec
    String authorization = context.authorization

    AuthProxyTool authProxyTool = ec.getFactory().getTool("AuthProxy", AuthProxyTool.class)
    authProxyTool.shiroSetUser(authProxyTool.decodeAuthorization(authorization), ec.web.session)

    return [:]
}

public Map<String, Object> createAccount() {
    List<Map<String, Object>> providers = context.providers
    return createOrAttachAccount(null, providers)
}

public Map<String, Object> attachAccount() {
    String partyId = context.partyId
    List<Map<String, Object>> providers = context.providers
    return createOrAttachAccount(partyId, providers)
}

private Map<String, Object> createOrAttachAccount(String partyId, List<Map<String, Object>> providers) {
    logger.info('createOrAttachAccount:' + partyId)

    logger.info('providers:' + providers)

    ExecutionContext ec = context.ec
    List<Map<String, Object>> profiles = context.profiles

    Map<String, Map<String, Object>> parsedProviderData = [:]

    Set<String> foundPartyIds = []

    List<EntityValue> oldAuthContactMech = []
    List<EntityValue> newAuthContactMech = []

    // Update each provider profile
    for (Map<String, Object> providerData: providers) {
        String name = providerData.name
        Map<String, Object> profile = providerData.profile
        Object token = providerData.token
        String id = profile.id

        Map<String, Object> parsedProfileData = [name: name, id: id, profile: profile]

        logger.info('profile(' + name + '):' + id)

        EntityValue providerEnumeration = ec.entity.find('moqui.basic.Enumeration').condition([enumTypeId: 'PJSContactMech']).one()
        if (!providerEnumeration) {
            providerEnumeration = ec.entity.makeValue('moqui.basic.Enumeration').setAll([
                enumTypeId: 'PJSContactMech',
                parentEnumId: 'PJSContactMech',
                enumCode: name,
                description: name,
            ]).setSequencedIdPrimary().createOrUpdate()
        }
        parsedProfileData.enumeration = providerEnumeration
        //providerToEnumerationId[name] = providerEnumeration.enumId

        EntityValue providerContactMech
        EntityValue providerContactMechInfo = ec.entity.find('bf.auth.AuthContactMechInfo').condition([
            contactMechTypeEnumId: providerEnumeration.enumId,
            providerId: id,
        ]).useCache(false).one()
        if (providerContactMechInfo) {
            providerContactMech = providerContactMechInfo.findRelatedOne('bf.auth.AuthContactMech', false, true)
        } else {
            EntityValue baseContactMech = ec.entity.makeValue('mantle.party.contact.ContactMech').setAll([
                contactMechTypeEnumId: providerEnumeration.enumId,
            ]).setSequencedIdPrimary().createOrUpdate()
            providerContactMech = ec.entity.makeValue('bf.auth.AuthContactMech').setAll([
                contactMechId: baseContactMech.contactMechId,
                //contactMechTypeEnumId: providerEnumeration.enumId,
                providerId: id,
            ])
        }
        providerContactMech.profileJson = JsonOutput.toJson(profile)
        providerContactMech.tokenJson = JsonOutput.toJson(token)
        providerContactMech.createOrUpdate()
    //]).useCache(true).conditionDate('fromDate', 'thruDate', now).list()
        EntityFind acmsFind = ec.entity.find('bf.auth.AuthContactMechsInfo').condition([
            authContactMechID: providerContactMech.contactMechId,
            //contactMechTypeEnumId: 'CmtEmailAddress',
            contactMechPurposeId: 'BF_AUTH',
        ]).conditionDate('fromDate', 'thruDate', now)

        Set<String> newEmailSet = []
        for (Map<String, Object> profileEmail: profile.emails) {
            newEmailSet.add(profileEmail.value)
        }
        logger.info('newEmailSet:' + newEmailSet)

        EntityList acmsValues = acmsFind.list()
        for (EntityValue acmsValue: acmsValues) {
            switch (acmsValue.contactMechTypeEnumId) {
                case 'CmtEmailAddress':
                    if (!newEmailSet.remove(acmsValue.infoString)) {
                        // existing email in database is not in the new set from the provider,
                        ec.entity.find('bf.auth.AuthContactMechs').condition([
                            authContactMechId: providerContactMech.contactMechId,
                            contactMechId: acmsValue.contactMechId,
                            contactMechPurposeId: 'BF_AUTH',
                            fromDate: acmsValue.fromDate,
                        ]).updateAll([thruDate: now])
                    }
                    break
            }
        }

        for (String newEmail: newEmailSet) {
            EntityValue emailCM = ec.entity.find('mantle.party.contact.ContactMech').condition([
                contactMechTypeEnumId: 'CmtEmailAddress',
                infoString: newEmail,
            ]).one()
            if (!emailCM) {
                emailCM = ec.entity.makeValue('mantle.party.contact.ContactMech').setAll([
                    contactMechTypeEnumId: 'CmtEmailAddress',
                    infoString: newEmail,
                ]).setSequencedIdPrimary().createOrUpdate()
            }
            ec.entity.makeValue('bf.auth.AuthContactMechs').setAll([
                authContactMechId: providerContactMech.contactMechId,
                contactMechId: emailCM.contactMechId,
                contactMechPurposeId: 'BF_AUTH',
                fromDate: now,
            ]).createOrUpdate()
        }

        parsedProfileData.contactMech = providerContactMech
        //providerToContactMechId[name] = providerContactMech.contactMechId

        EntityValue existingPartyView = ec.entity.find('mantle.party.contact.PartyContactMech').condition([
            contactMechId: providerContactMech.contactMechId,
            contactMechPurposeId: 'BF_AUTH',
        ]).conditionDate('fromDate', 'thruDate', now).one()
        if (existingPartyView) {
            String existingPartyId = existingPartyView.partyId
            parsedProfileData.partyId = existingPartyId
            foundPartyIds.add(existingPartyId)
        }

        parsedProviderData[name] = parsedProfileData
    }

    logger.info('given partyId: ' + partyId)
    if (partyId == null) {
        if (foundPartyIds.size() == 0) {
            // nothing, will create a new Party
        } else if (foundPartyIds.size() == 1) {
            partyId = foundPartyIds.iterator().next()
            logger.info('found partyId:' + partyId)
        } else {
            throw new Exception('overlapping profiles')
        }
    } else {
        foundPartyIds.add(partyId)
    }
    EntityValue person = null
    if (partyId == null) {
        partyId = ec.entity.makeValue('Party').setAll([
            partyTypeEnumId: 'PtyPerson',
        ]).setSequencedIdPrimary().createOrUpdate().partyId
        person = ec.entity.makeValue('Person').setAll([
            partyId: partyId,
        ])
        logger.info('created partyId:' + partyId)
    } else {
        person = ec.entity.find('Person').condition('partyId', partyId).one()
    }

    EntityValue userAccount = ec.entity.find('UserAccount').condition(['partyId': partyId, isAuthAccount: 'Y']).one()
    if (userAccount == null) {
        userAccount = ec.entity.makeValue('UserAccount').setAll([
            partyId: partyId,
            isAuthAccount: 'Y',
        ]).setSequencedIdPrimary().createOrUpdate()
    }
    if (!userAccount.username) {
        logger.info('no username')
        while (true) {
            String randomUsername = RandomStringUtils.randomAlphanumeric(24)
            logger.info('trying random username:' + randomUsername)
            if (ec.entity.find('UserAccount').condition([username: randomUsername]).one() == null) {
                userAccount.username = randomUsername
                userAccount.update()
                break
            }
        }
    }
    logger.info('username:' + userAccount.username)
    if (false) if (!userAccount.currentPassword) {
        String randomPassword = RandomStringUtils.randomAlphanumeric(24) + '-'

        userAccount.currentPassword = Base64.getEncoder().encodeToString(randomPassword.getBytes())
        userAccount.passwordHashType = 'none'
        userAccount.passwordBase64 = 'Y'
        userAccount.update()
        // FIXME: loop the service calls
        if (false)
        ec.service.sync().name('org.moqui.impl.UserServices.update#Password').parameters([
            userId: userAccount.userId,
            oldPassword: 'a',
            newPassword: randomPassword,
            newPasswordVerify: randomPassword,
        ]).call()
        /*

        RandomStringUtils.random(24)
        def passwordConfig = ec.executionContextFactory.confXmlRoot.first('user-facade').first('password')

        passwordNode.attribute('min-length')

        passwordNode.attribute('min-digits')
        int digits = ObjectUtilities.countChars(newPassword, true, false, false)

        passwordNode.attribute('min-others')
        int others = ObjectUtilities.countChars(newPassword, false, false, true)
        */
    }

    for (Map<String, Object> parsedProfileData: parsedProviderData.values()) {
        String name = parsedProfileData.name
        String id = parsedProfileData.id
        Map<String, Object> profile = parsedProfileData.profile
        logger.info('profile(' + name + '):' + id)

        // First provider that has the info, gets to set it, but only once.
        // TODO: Record the provider that provided these fields, and allow
        // for updates.
        if (profile.displayName) {
            if (!person.nickname) {
                person.nickname = profile.displayName
            }
            if (!userAccount.userFullName) {
                userAccount.userFullName = profile.displayName
            }
        }
        if (profile.name) {
            if (!person.firstName && !person.lastName) {
                person.firstName = profile.name.givenName
                person.lastName = profile.name.familyName
            }
        }
        if (!person.gender) {
            if (profile.gender == 'male') {
                person.gender = 'M'
            } else if (profile.gender == 'female') {
                person.gender = 'F'
            }
        }

        String foundPartyId = parsedProfileData.partyId
        String providerContactMechId = parsedProfileData.contactMech.contactMechId
        if (foundPartyId != null) {
            if (foundPartyId != partyId) {
                // move the profile from the other user to this user
                ec.entity.find('mantle.party.contact.PartyContactMech').condition([partyId: foundPartyId, contactMechId: providerContactMechId]).updateAll([thruDate: now])
                ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
                    partyId: partyId,
                    contactMechId: providerContactMechId,
                    contactMechPurposeId: 'BF_AUTH',
                    fromDate: now,
                ]).createOrUpdate()
            }
        } else {
            // no mapping for this provider, connect it
            ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
                partyId: partyId,
                contactMechId: providerContactMechId,
                contactMechPurposeId: 'BF_AUTH',
                fromDate: now,
            ]).createOrUpdate()
        }
    }

    person.createOrUpdate()

    for (String foundPartyId: foundPartyIds) {
        logger.info('process party:' + foundPartyId)
        // Find all the providers for this party
        EntityList partyProviderValues = ec.entity.find('bf.auth.PartyAuthContactMech').condition('partyId', foundPartyId).conditionDate('fromDate', 'thruDate', now).list()

        Set<String> allPhotos = []

        // coalesce the emails(multiple providers might have the same email registered
        Map<String, String> emailToCMId = [:]
        for (EntityValue partyProviderValue: partyProviderValues) {
            logger.info('provider:' + partyProviderValue)
            Map<String, Object> profile = new JsonSlurper().parseText(partyProviderValue.profileJson)

            EntityList providerCMs = ec.entity.find('bf.auth.AuthContactMechsInfo').condition([
                authContactMechId: partyProviderValue.contactMechId,
            ]).conditionDate('fromDate', 'thruDate', now).list()
            for (EntityValue providerCM: providerCMs) {
                switch (providerCM.contactMechTypeEnumId) {
                    case 'CmtEmailAddress':
                        emailToCMId[providerCM.infoString] = providerCM.contactMechId
                        if (!userAccount.emailAddress) {
                            userAccount.emailAddress = providerCM.infoString
                        }
                        break
                }
            }

            for (Map<String, Object> photo: profile.photos) {
                allPhotos.add(photo.value)
            }
        }
        logger.info('emailToCMId:' + emailToCMId)

        EntityList partyCMs = ec.entity.find('mantle.party.contact.PartyContactMechInfo').condition([
            partyId: foundPartyId,
            contactMechPurposeId: 'BF_AUTH',
        ]).conditionDate('fromDate', 'thruDate', now).list()
        for (EntityValue partyCM: partyCMs) {
            switch (partyCM.contactMechTypeEnumId) {
                case 'CmtEmailAddress':
                    if (!emailToCMId.remove(partyCM.infoString)) {
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
            ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
                partyId: foundPartyId,
                contactMechId: emailEntry.value,
                contactMechPurposeId: 'BF_AUTH',
                fromDate: now,
            ]).createOrUpdate()
        }

        EntityList photoValues = ec.entity.find('mantle.party.PartyContent').condition([
            partyId: foundPartyId,
            partyContentTypeEnumId: 'PcntPrimaryImage',
        ]).list()
        for (EntityValue photoValue: photoValues) {
            if (!allPhotos.remove(photoValue.contentLocation)) {
                photoValue.delete()
            }
        }

        for (String photo: allPhotos) {
            ec.entity.makeValue('mantle.party.PartyContent').setAll([
                partyId: foundPartyId,
                partyContentTypeEnumId: 'PcntPrimaryImage',
                contentLocation: photo,
            ]).setSequencedIdPrimary().createOrUpdate()
        }
    }
    userAccount.update()

    return [partyId: partyId]
}

/*
String getHash(String text) {
    MessageDigest md = MessageDigest.getInstance('SHA')
    md.update(text.getBytes())
    return Base64.getEncoder().encodeToString(md.digest())
}
*/

private byte[] adjustSalt(byte[] possibleSalt, int length) {
    if (possibleSalt.length == length) {
        return possibleSalt
    } else {
        byte[] actualSalt = new byte[length]
        int before = (length - possibleSalt.length) / 2
        int after = length - possibleSalt.length - before
        logger.info("adjustSalt: givenLength=${possibleSalt.length} before=${before} after=${after}")
        if (possibleSalt.length < length) {
            int i = 0;
            for (; i < before; i++) actualSalt[i] = 0x12
            System.arraycopy(possibleSalt, 0, actualSalt, i, possibleSalt.length)
            i += possibleSalt.length
            for (; i < length; i++) actualSalt[i] = 0x34
        } else {
            System.arraycopy(possibleSalt, -before, actualSalt, 0, possibleSalt.length + before + after)
        }
        return actualSalt
    }
}

private Cipher createCipher(boolean encrypt) {
    // FIXME: copy from config
    String password = '7cdfd788fb8befabb4d08c4ff51f94c59bbc52fa40df37b490e675f0dd21d350'
    byte[] salt = adjustSalt('FIXMESALT568'.getBytes(), 8)
    int count = 5
    String algorithm = 'PBEWithMD5AndDES'

    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count)
    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray())

    SecretKeyFactory keyFac = SecretKeyFactory.getInstance(algorithm)
    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec)
    Cipher pbeCipher = Cipher.getInstance(algorithm)
    pbeCipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec)

    return pbeCipher
}

private String encryptValue(String value) {
    return Base64.getUrlEncoder().encodeToString(createCipher(true).doFinal(value.getBytes()))
}

private String decryptValue(String value) {
    logger.info("decryptValue($value)")
    return new String(createCipher(false).doFinal(Base64.getUrlDecoder().decode(value)))
}

public Map<String, Object> sendEmailLogin() {
    logger.info('sendEmailLogin')
    ExecutionContext ec = context.ec
    String emailAddress = context.emailAddress
    String partyId = context.partyId

    long now = System.currentTimeMillis()
    List<Object> payload = [now, emailAddress, partyId]
    String payloadJson = JsonOutput.toJson(payload)

    hash = encryptValue(payloadJson)
    logger.info("payload=${payload} => ${hash}")

    return [:]
}

public Map<String, Object> verifyEmailLogin() {
    logger.info('verifyEmailLogin')
    ExecutionContext ec = context.ec
    String hash = context.hash
    String payloadJson = decryptValue(hash)

    List<Object> payload = new JsonSlurper().parseText(payloadJson)

    long now = System.currentTimeMillis()
    long requestTime = payload[0]
    String emailAddress = payload[1]
    String partyId = payload[2]

    logger.info("hash=${hash} => ${payload}")

    return [:]
}

public Map<String, Object> me() {
    logger.info('me')

    ExecutionContext ec = context.ec
    String partyId = context.partyId

    EntityList providerContactMechs = ec.entity.find('bf.auth.PartyAuthContactMech').condition([
        partyId: partyId,
    ]).useCache(true).conditionDate('fromDate', 'thruDate', now).list()

    Set<String> emailSet = []
    String profilePic = null
    String displayName = null

    if (providerContactMechs.isEmpty()) {
        partyId = null
        return [partyId: partyId]
    }

    // TODO: use the normalized data structures, not the json

    for (EntityValue providerContactMech: providerContactMechs) {
        Map<String, Object> profile = new JsonSlurper().parseText(providerContactMech.profileJson)
        logger.info('profile:' + profile)
        for (Map<String, Object> profileEmail: profile.emails) {
            emailSet.add(profileEmail.value)
        }
        if (!profilePic && profile.photos) {
            profilePic = profile.photos[0].value
        }
        if (!displayName && profile.displayName) {
            displayName = profile.displayName
        }
    }

    return [
        partyId: partyId,
        profilePic: profilePic,
        displayName: displayName,
        emails: (emailSet as List).sort(),
    ]
}

private Map<String, Object> getProviderJson(fieldName) {
    logger.info('getProviderJson:' + fieldName)

    ExecutionContext ec = context.ec
    String partyId = context.partyId
    String providerName = context.providerName

    EntityValue providerEnumeration = ec.entity.find('moqui.basic.Enumeration').condition([enumTypeId: 'PJSContactMech', enumCode: providerName]).one()
    if (!providerEnumeration) {
        return null
    }

    EntityValue providerContactMech = ec.entity.find('bf.auth.PartyAuthContactMech').condition([
        contactMechTypeEnumId: providerEnumeration.enumId,
        partyId: partyId,
    ]).useCache(true).conditionDate('fromDate', 'thruDate', now).one()

    logger.info('providerContactMech=' + providerContactMech)
    if (!providerContactMech) {
        return null
    }

    Object value = new JsonSlurper().parseText(providerContactMech[fieldName])
    logger.info('value=' + value)
    return value
}

Map<String, Object> getProviderProfile() {
    Object providerProfile = getProviderJson('profileJson')
    return [providerProfile: providerProfile]
}

private String getMoquiAuthorizationHeader() {
    // Proof of Concept Hack: The username/password are random, and stored unhashed.
    ExecutionContext ec = context.ec
logger.info('sessionAttributes.keySet=' + ec.web.sessionAttributes.keySet())
logger.info('sessionAttributes.toString()=' + ec.web.sessionAttributes.toString())
logger.info('sessionAttributes=' + ec.web.sessionAttributes)
    String partyId = context.partyId
    EntityValue userAccount = ec.entity.find('moqui.security.UserAccount').condition([partyId: partyId, isAuthAccount: 'Y']).one()


    AuthProxyTool authProxyTool = ec.factory.getTool("AuthProxy", AuthProxyTool.class)
    return authProxyTool.buildAuthorizationHeader(userAccount)
}

Map<String, Object> getProviderToken() {
    String providerName = context.providerName
    Object providerToken = providerName == 'moqui' ? getMoquiAuthorizationHeader() : getProviderJson('tokenJson')
    return [providerToken: providerToken]
}

Map<String, Object> getProviderTokens() {
    logger.info('getProviderTokens')

    ExecutionContext ec = context.ec
    String partyId = context.partyId

    EntityList providerContactMechs = ec.entity.find('bf.auth.PartyAuthContactMech').condition([
        partyId: partyId,
    ]).useCache(true).conditionDate('fromDate', 'thruDate', now).list()

    Map<String, Object> providerTokens = [:]
    for (EntityValue providerContactMech: providerContactMechs) {
        EntityValue providerEnumeration = ec.entity.find('moqui.basic.Enumeration').condition([enumId: providerContactMech.contactMechTypeEnumId]).one()
        String providerName = providerEnumeration.enumCode
        providerTokens[providerName] = new JsonSlurper().parseText(providerContactMech.tokenJson)
    }
    providerTokens.moqui = getMoquiAuthorizationHeader()
    return [providerTokens: providerTokens]
}
