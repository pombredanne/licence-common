/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.omnifone.licence.common;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import junit.framework.Assert;
import org.testng.annotations.Test;
import java.text.SimpleDateFormat;
/**
 *
 * @author ekarincaoglu
 */
public class TrackLicenceTokenTest {
    
    final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    @Test
    public void testConsumeValidToken() throws NoSuchAlgorithmException, InvalidKeyException, ParseException {
        Date date = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1));
        String token = TrackLicenceToken.toToken(formatter.format(date),"0123456789abcdef0123456789abcdef", "subscription", "GB");
        Assert.assertEquals(true, TrackLicenceToken.isValid(token,"0123456789abcdef0123456789abcdef", "subscription", "GB"));
             
    }
    
    @Test    
    public void testConsumeInvalidTokenInvalidTrack() throws NoSuchAlgorithmException, InvalidKeyException, ParseException {
     
        Date date = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1));
        String token = TrackLicenceToken.toToken(formatter.format(date),"0123456789abcdef0123456789abcdef", "subscription", "GB");
        // notice different track id
        Assert.assertEquals(false, TrackLicenceToken.isValid(token,"0123456789abcdef0123456789abcdea", "subscription", "GB"));
             
    }    
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void isValidInvalidParam() throws NoSuchAlgorithmException, InvalidKeyException, ParseException {     
        TrackLicenceToken.isValid(null, null, null, null);
             
    }    
}
