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
/*
    <moqui.basic.EnumerationType description="PassportJS Provider" enumTypeId="PJSContactMech"/>
    <moqui.basic.Enumeration description="PassportJS Provider" enumId="PJSContactMech" enumTypeId="ContactMechType" parentEnumId="CmtElectronicAddress"/>
    <moqui.basic.Enumeration description="Facebook" enumCode="facebook" enumId="PJS_FACEBOOK" enumTypeId="PJSContactMech" parentEnumId="PJSContactMech"/>
*/

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

    EntityValue providerContactMech = ec.entity.find('bf.auth.AuthContactMech').condition([
        contactMechTypeEnumId: providerEnumeration.enumId,
        providerId: id,
    ]).useCache(false).one()
    if (!providerContactMech) {
        EntityValue baseContactMech = ec.entity.makeValue('mantle.party.contact.ContactMech').setAll([
            contactMechTypeEnumId: providerEnumeration.enumId,
        ]).setSequencedIdPrimary().createOrUpdate()
        providerContactMech = ec.entity.makeValue('bf.auth.AuthContactMech').setAll([
            contactMechId: baseContactMech.contactMechId,
            contactMechTypeEnumId: providerEnumeration.enumId,
            providerId: id,
        ])
    }
//]).useCache(true).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()
    if (providerContactMech.providerJson) {
        Map<String, Object> oldProfile = new JsonSlurper().parseText(providerContactMech.providerJson)
        Set<String> oldEmailSet = []
        for (Map<String, Object> oldProfileEmail: oldProfile.emails) {
            oldEmailSet.add(oldProfileEmail.value)
        }
        Set<String> oldEmailSet = []
        for (Map<String, Object> profileEmail: profile.emails) {
            oldEmailSet.remove(profileEmail.value)
        }
        // oldEmailSet contains emails that are not in the new profile info
        // any new emails will be attached later on
        EntityFind pcmiFind = ec.entity.find('bf.auth.AuthContactMechs').condition([
            contactMechTypeEnumId: 'CmtEmailAddress',
            contactMechPurposeId: 'BF_AUTH',
        ]).condition(ec.conditionFactory.makeCondition('infoString', EntityCondition.Operator.IN, oldEmailSet)).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp)
        EntityList oldEmailCMs = pcmiFind.list()
        for (EntityValue oldEmailCM: oldEmailCMs) {
            oldEmailCM.thruDate = ec.user.nowTimestamp
            oldEmailCM.update()
        }
    }
    providerContactMech.providerJson = JsonOutput.toJson(profileData)
    providerContactMech.createOrUpdate()
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

/*
PartyContent
    .partyId
    .partyContentTypeEnumId = 'PcntFaceImage'
    .contentLocation = $url
Person
    .nickName = $displayName
*/

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

/*
    <entity entity-name="AuthContactMech" package="bf.auth">
        <field name="contactMechId" type="id" is-pk="true"/>
        <field name="providerId" type="text-medium"/>
        <field name="providerJson" type="text-very-long"/>
        <relationship type="one" related="mantle.party.contact.ContactMech"/>
        <relationship type="many" related="mantle.party.contact.ContactMech"/>
        <relationship type="many" related="bf.auth.AuthContactMechs" short-alias="authContactMechs">
            <key-map fieldName="contactMechId" related="authContactMechId"/>
        </relationship>
    </entity>
    <entity entity-name="AuthContactMechs" package="bf.auth">
        <field name="authContactMechId" type="id" is-pk="true"/>
        <field name="contactMechId" type="id" is-pk="true"/>
        <field name="contactMechPurposeId" type="id" is-pk="true"/>
        <field name="fromDate" type="date-time" is-pk="true"/>
        <field name="thruDate" type="date-time"/>
        <relationship type="one" related="bf.auth.AuthContactMech" short-alias="authContactMech">
            <key-map fieldName="authContactMechId" related="contactMechId"/>
        </relationship>
        <relationship type="one" related="mantle.party.contact.ContactMech" short-alias="contactMech" />
        <relationship type="one" related="mantle.party.contact.ContactMechPurpose" short-alias="contactMechPurpose"/>
    </entity>
    for (Map<String, Object> profileEmail: profile.emails) {
        emailSet.add(profileEmail.value)
    }
*/


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

            Set<String> profileEmails = []
            for (Map<String, Object> profileEmail: profile.emails) {
                profileEmails.add(profileEmail.value)
            }


        // oldEmailSet contains emails that are not in the new profile info
        // any new emails will be attached later on
        EntityFind pcmiFind = ec.entity.find('mantle.party.contact.PartyContactMechInfo').condition([
            contactMechTypeEnumId: 'CmtEmailAddress',
            contactMechPurposeId: 'BF_AUTH',
        ]).condition(ec.conditionFactory.makeCondition('infoString', EntityCondition.Operator.IN, oldEmailSet)).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp)
        EntityList oldEmailCMs = pcmiFind.list()
        for (EntityValue oldEmailCM: oldEmailCMs) {
            oldEmailCM.thruDate = ec.user.nowTimestamp
            oldEmailCM.update()
        }



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





/*
Set<String> emailSet = []
profilePic = null
displayName = null

if (providerContactMechs.isEmpty()) {
    partyId = null
    return
}
for (EntityValue providerContactMech: providerContactMechs) {
    Map<String, Object> providerData = new JsonSlurper().parseText(providerContactMech.providerJson)
    logger.info('providerData:' + providerData)
    String providerName = providerData.name
    Map<String, Object> profile = providerData.profile
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
emails = (emailSet as List).sort()
*/
