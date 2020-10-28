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

// org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("findParty")

// partyId
// profiles

Logger logger = LoggerFactory.getLogger("Me")
logger.info('Me.groovy')

ExecutionContext ec = context.ec

EntityList providerContactMechs = ec.entity.find('bf.auth.PartyAuthContactMech').condition([
    partyId: partyId,
]).useCache(true).conditionDate('fromDate', 'thruDate', ec.user.nowTimestamp).list()

Set<String> emailSet = []
profilePic = null
displayName = null

if (providerContactMechs.isEmpty()) {
    partyId = null
    return
}

// TODO: use the normalized data structures, not the json

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

