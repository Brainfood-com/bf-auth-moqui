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

import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityCondition
import org.moqui.entity.EntityFind
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue
import org.slf4j.Logger
import org.slf4j.LoggerFactory

// partyId
// profiles
Logger logger = LoggerFactory.getLogger("AttachAccount")
logger.info('AttachAccount.groovy')

logger.info('profiles:' + context.profiles)

ExecutionContext ec = context.ec
Map<String, Map<String, Object>> parsedProviderData = [:]

Set<String> foundPartyIds = []

List<EntityValue> oldAuthContactMech = []
List<EntityValue> newAuthContactMech = []

// Update each provider profile
for (Map<String, Object> profileData: context.profiles) {
    String name = profileData.name
    Map<String, Object> profile = profileData.profile
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
    providerContactMech.providerJson = JsonOutput.toJson(profileData)
    providerContactMech.createOrUpdate()
//]).useCache(true).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()
    EntityFind acmsFind = ec.entity.find('bf.auth.AuthContactMechsInfo').condition([
        authContactMechID: providerContactMech.contactMechId,
        //contactMechTypeEnumId: 'CmtEmailAddress',
        contactMechPurposeId: 'BF_AUTH',
    ]).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp)

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
                    ]).updateAll([thruDate: ec.user.nowTimestamp])
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
            fromDate: ec.user.nowTimestamp,
        ]).createOrUpdate()
    }

    parsedProfileData.contactMech = providerContactMech
    //providerToContactMechId[name] = providerContactMech.contactMechId

    EntityValue existingPartyView = ec.entity.find('mantle.party.contact.PartyContactMech').condition([
        contactMechId: providerContactMech.contactMechId,
        contactMechPurposeId: 'BF_AUTH',
    ]).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).one()
    if (existingPartyView) {
        String partyId = existingPartyView.partyId
        parsedProfileData.partyId = partyId
        foundPartyIds.add(partyId)
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

for (Map<String, Object> parsedProfileData: parsedProviderData.values()) {
    String name = parsedProfileData.name
    String id = parsedProfileData.id
    Map<String, Object> profile = parsedProfileData.profile
    logger.info('profile(' + name + '):' + id)

    // First provider that has the info, gets to set it, but only once.
    // TODO: Record the provider that provided these fields, and allow
    // for updates.
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
            ec.entity.find('mantle.party.contact.PartyContactMech').condition([partyId: foundPartyId, contactMechId: providerContactMechId]).updateAll([thruDate: ec.user.nowTimestamp])
            ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
                partyId: partyId,
                contactMechId: providerContactMechId,
                contactMechPurposeId: 'BF_AUTH',
                fromDate: ec.user.nowTimestamp,
            ]).createOrUpdate()
        }
    } else {
        // no mapping for this provider, connect it
        ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
            partyId: partyId,
            contactMechId: providerContactMechId,
            contactMechPurposeId: 'BF_AUTH',
            fromDate: ec.user.nowTimestamp,
        ]).createOrUpdate()
    }
}

person.createOrUpdate()

for (String foundPartyId: foundPartyIds) {
    logger.info('process party:' + foundPartyId)
    // Find all the providers for this party
    EntityList partyProviderValues = ec.entity.find('bf.auth.PartyAuthContactMech').condition('partyId', foundPartyId).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()

    Set<String> allPhotos = []

    // coalesce the emails(multiple providers might have the same email registered
    Map<String, String> emailToCMId = [:]
    for (EntityValue partyProviderValue: partyProviderValues) {
        logger.info('provider:' + partyProviderValue)
        Map<String, Object> providerData = new JsonSlurper().parseText(partyProviderValue.providerJson)
        Map<String, Object> profile = providerData.profile

        EntityList providerCMs = ec.entity.find('bf.auth.AuthContactMechsInfo').condition([
            authContactMechId: partyProviderValue.contactMechId,
        ]).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()
        for (EntityValue providerCM: providerCMs) {
            switch (providerCM.contactMechTypeEnumId) {
                case 'CmtEmailAddress':
                    emailToCMId[providerCM.infoString] = providerCM.contactMechId
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
    ]).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()
    for (EntityValue partyCM: partyCMs) {
        switch (partyCM.contactMechTypeEnumId) {
            case 'CmtEmailAddress':
                if (!emailToCMId.remove(partyCM.infoString)) {
                    ec.entity.find('mantle.party.contact.PartyContactMech').condition([
                        contactMechId: partyCM.contactMechId,
                        partyId: partyCM.partyId,
                        contactMechPurposeId: 'BF_AUTH',
                        fromDate: partyCM.fromDate,
                    ]).updateAll([thruDate: ec.user.nowTimestamp])
                }
                break
        }
    }
    for (Map.Entry<String, String> emailEntry: emailToCMId.entrySet()) {
        ec.entity.makeValue('mantle.party.contact.PartyContactMech').setAll([
            partyId: foundPartyId,
            contactMechId: emailEntry.value,
            contactMechPurposeId: 'BF_AUTH',
            fromDate: ec.user.nowTimestamp,
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

