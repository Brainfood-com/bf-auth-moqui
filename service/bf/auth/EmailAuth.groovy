import groovy.json.JsonOutput
import groovy.transform.Field


import java.util.Base64
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.slf4j.Logger
import org.slf4j.LoggerFactory



import groovy.json.JsonSlurper

import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityCondition
import org.moqui.entity.EntityFind
import org.moqui.entity.EntityList
import org.moqui.entity.EntityValue


@Field Logger logger = LoggerFactory.getLogger("EmailAuth")

/*
String getHash(String text) {
    MessageDigest md = MessageDigest.getInstance('SHA')
    md.update(text.getBytes())
    return Base64.getEncoder().encodeToString(md.digest())
}

*/

byte[] adjustSalt(byte[] possibleSalt, int length) {
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

Cipher createCipher(boolean encrypt) {
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

String encryptValue(String value) {
    return Base64.getUrlEncoder().encodeToString(createCipher(true).doFinal(value.getBytes()))
}

String decryptValue(String value) {
    logger.info("decryptValue($value)")
    return new String(createCipher(false).doFinal(Base64.getUrlDecoder().decode(value)))
}

void sendEmailLogin() {
    logger.info('sendEmailLogin')
    ExecutionContext ec = context.ec
    String emailAddress = context.emailAddress
    String partyId = context.partyId

    long now = System.currentTimeMillis()
    List<Object> payload = [now, emailAddress, partyId]
    String payloadJson = JsonOutput.toJson(payload)

    hash = encryptValue(payloadJson)
    logger.info("payload=${payload} => ${hash}")

}

void verifyEmailLogin() {
    logger.info('verifyEmailLogin')
    ExecutionContext ec = context.ec
    String hash = context.hash
    String payloadJson = decryptValue(hash)

    List<Object> payload = new JsonSlurper().parseText(payloadJson)

    long now = System.currentTimeMillis()
    long requestTime = payload[0]
    emailAddress = payload[1]
    partyId = payload[2]

    logger.info("hash=${hash} => ${payload}")
}
