/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.omnifone.licence.common;



import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author ekarincaoglu
 */
public final class TrackLicenceToken {
    private final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TrackLicenceToken.class.getName());
    private static final byte TOKEN_FIELD_INDEX_SIGNATURE = 0;
    private static final byte TOKEN_FIELD_INDEX_EXPIRY_DATE = 1;
    private static final byte TOKEN_FIELDS = 2;
    private static final String PATTERN_EXPIRY_DATE = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static final String key = "3feeTa7gHSJbevpQpuSGTBU759QwkU2y";
    private static final SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1"); 

    private TrackLicenceToken() {
        
    }

    // expiry date format is yyyy-MM-dd'T'HH:mm:ss'Z'
    public static String toToken(String expiryDate,String trackId, String right, String country) {
        try {
            String signature = toSignature(trackId, right, expiryDate, country);
            String token = signature + "," + expiryDate;
            return new String(Base64.encodeBase64(token.getBytes()));
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(String.format("Unable to generate token NoSuchAlgorithmException.date=%s trackId=%s right=%s country=%s", expiryDate,trackId,right,country) , ex);
        } catch (InvalidKeyException ex) {
            throw new RuntimeException(String.format("Unable to generate token InvalidKeyException. date=%s trackId=%s right=%s country=%s", expiryDate,trackId,right,country) , ex);
        }
    }
   
    
    // Mac is not thread-safe. 
    private static final ThreadLocal<Mac> localmac = new ThreadLocal<Mac>() {

        @Override
        protected Mac initialValue() {
            try {
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(signingKey);                
                return mac;
            } catch (NoSuchAlgorithmException ex) {
                // never really happens
                throw new IllegalArgumentException(ex);
            } catch (InvalidKeyException ex) {
                // never really happens
                throw new IllegalArgumentException(ex);
            }
        }
        
    };
    
    private static String toSignature(String trackId, String right, String expiryDate, String country)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String data = trackId.concat(right).concat(expiryDate).concat(country);
        Mac mac = localmac.get();        
        byte[] result = mac.doFinal(data.getBytes());
        byte[] resultBase64 = Base64.encodeBase64(result);
        return new String(resultBase64);
    }
    
    

    
    public static boolean isValid(String token, String trackId, String right, String country) {

        notNull(trackId, "trackId");
        notNull(right, "right");
        notNull(country, "country");
        notNull(token, "token");        
        // Parse token.
        String[] fields = new String(Base64.decodeBase64(token)).split(",");
        
        if (fields.length != TOKEN_FIELDS) {
            logger.info("Token does not contain expected {} tokens {}", TOKEN_FIELDS, fields);
            
            return false;
        }
        
        String tokenSignature = fields[TOKEN_FIELD_INDEX_SIGNATURE];
        String tokenExpiryDate = fields[TOKEN_FIELD_INDEX_EXPIRY_DATE];
        
        // Validate signature.
        try {
            String expectedSignature = toSignature(trackId, right, tokenExpiryDate, country);
            
            if (!expectedSignature.equals(tokenSignature)) {
                logger.info("Signature in token [{}] does not match expected signature [{}], calculated from track ID [{}], right [{}], expiry date [{}], and country [{}]",
                        tokenSignature, expectedSignature, trackId, right, tokenExpiryDate, country);
                
                return false;
            }
        } catch (NoSuchAlgorithmException ex) {
            logger.error("Error validating token", ex);
            
            return false;
        } catch (InvalidKeyException ex) {
            logger.error("Error validating token", ex);
            
            return false;
        }
        
        // Validate expiry date.
        try {
            DateFormat dateFormat = new SimpleDateFormat(PATTERN_EXPIRY_DATE);
            Date expiryDate = dateFormat.parse(tokenExpiryDate);
            
            if (new Date().after(expiryDate)) {
                logger.info("Token expired at {}.", expiryDate);
                
                return false;
            }
        } catch (ParseException ex) {
            logger.info("Expiry date in token [{}] does not have expected format {}",
                    tokenExpiryDate, PATTERN_EXPIRY_DATE);
            
            return false;
        }
        
        // If execution reaches this point, then the token is valid.
        
        return true;
    }  
    static <T> T notNull(final T argument, final String name) {
        if (argument == null) {
            throw new IllegalArgumentException("Argument '" + name + "' may not be null.");
        }
        return argument;
    }
}
