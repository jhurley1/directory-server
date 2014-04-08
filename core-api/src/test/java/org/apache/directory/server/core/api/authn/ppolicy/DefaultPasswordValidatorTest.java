/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.server.core.api.authn.ppolicy;


import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;


/**
 * This is the unit test for the 
 * org.apache.directory.server.core.api.authn.ppolicy.DefaultPasswordValidator Java class.
 */
public class DefaultPasswordValidatorTest
{
    @Test
    public void testWithValidPassword()
        throws Exception
    {
        DefaultPasswordValidator.INSTANCE.validate("wQe32veddM", "jdoe");
        
    }  //end method testWithValidPassword()
    
    
    @Test
    public void testPasswordContainingUsername()
    {
        //Check validation when user name is embedded at the beginning of the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("jdoe2344", "jdoe");
            fail("Expected to see an exception thrown when a password beginning with the user " +
                 "name was validated.");
        }
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("user name"));            
            
        }  //end catch block
        
        
        //Check validation when user name is embedded in the middle of the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("23jdoe44", "jdoe");
            fail("Expected to see an exception thrown when a password containing the user " +
                 "name was validated.");
        }
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("user name"));            
            
        }  //end catch block

        
        //Check validation when user name is at the end of the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("2344jdoe", "jdoe");
            fail("Expected to see an exception thrown when a password ending with the user " +
                 "name was validated.");
        }
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("user name"));            
            
        }  //end catch block
        
    }  //end method testPasswordContainingUsername()
    
    
    @Test
    public void testPasswordLackingRequiredGroup()
    {
        //Test with no lower case letter in the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("ABC123DE", "jdoe");
            fail("Expected to see an exception thrown when the password being validated did " +
                 "not contain a lower case letter.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("lower case"));
            
        }  //end catch block
        
        
        //Test with no upper case letter in the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("abc123de", "jdoe");
            fail("Expected to see an exception thrown when the password being validated did " +
                 "not contain an upper case letter.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("Upper case"));
            
        }  //end catch block
        
        
        //Test with no number in the password.
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("aBcDeFgH", "jdoe");
            fail("Expected to see an exception thrown when the password being validated did " +
                 "not contain a numeral.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("numeral"));
            
        }  //end catch block
        
    }  //end method testPasswordLackingRequiredGroup()
    
    
    @Test
    public void testPasswordWithTriplicates()
    {
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("abc1222ABC", "jdoe");
            fail("Expected to see an exception thrown when the password being validated " +
                 "contained at least 3 of the same characters in sequence.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("3 or more"));
            
        }  //end catch block
        
    }  //end method testPasswordWithTriplicates()
    
    
    @Test
    public void testPasswordWithOddMirror()
    {
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("a3Ver.reMeg", "jdoe");
            fail("Expected to see an exception thrown when the password being validated " +
                 "contained an odd mirror.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("sequence mirror"));
        
        }  //end catch block
        
    }  //end method testPasswordWithOddMirror()
    
    
    @Test
    public void testPasswordWithEvenMirror()
    {
        try
        {
            DefaultPasswordValidator.INSTANCE.validate("trMeeMg9", "jdoe");
            fail("Expected to see an exception thrown when the password being validated " +
                 "contained an even mirror.");
            
        }  //end try block
        catch(PasswordPolicyException ex)
        {
            assertTrue("The actual exception message was: " + ex.getMessage(),
                       ex.getMessage().contains("sequence mirror"));
        
        }  //end catch block
        
    }  //end method testPasswordWithEvenMirror()    
    
}  //end class DefaultPasswordValidatorTest

