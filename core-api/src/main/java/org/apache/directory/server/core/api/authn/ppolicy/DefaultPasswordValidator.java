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


/**
 * The default password validator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultPasswordValidator implements PasswordValidator
{

    /** the default validator's instance */
    public final static DefaultPasswordValidator INSTANCE = new DefaultPasswordValidator();


    /**
     * Creates a new instance of DefaultPasswordValidator.
     */
    public DefaultPasswordValidator()
    {
    }


    /**
     * {@inheritDoc}
     */
    public void validate( String password, String entryRdnVal ) throws PasswordPolicyException
    {
        checkUsernameSubstring(password, entryRdnVal);
        checkPasswordCharSet(password);
        checkSequentialCharacterOccurrences(password);
        checkForMirroredSequences(password);
    }


    /**
     * The password does not contain three letter (or more) tokens from the user's account name.
     *
     * If the account name is less than three characters long, this check is not performed
     * because the rate at which passwords would be rejected is too high. For each token that is
     * three or more characters long, that token is searched for in the password; if it is present,
     * the password change is rejected. For example, the name "First M. Last" would be split into
     * three tokens: "First", "M", and "Last". Because the second token is only one character long,
     * it would be ignored. Therefore, this user could not have a password that included either
     * "first" or "last" as a substring anywhere in the password. All of these checks are
     * case-insensitive.
     */
    private void checkUsernameSubstring(String password, String username) 
        throws PasswordPolicyException
    {
        if ( username == null || username.trim().length() == 0 )
        {
            return;
        }

        String[] tokens = username.split( "[^a-zA-Z]" );

        for ( String token : tokens )
        {
            if ( ( token == null ) || ( token.length() < 4 ) )
            {
                // Two short : continue with the next token
                continue;
            }

            if ( password.matches( "(?i).*" + token + ".*" ) )
            {
                throw new PasswordPolicyException("The password string cannot contain any part " +
                                                  "of your user name", 
                    5 );// 5 == PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY
            }
        }
    }
    
    
    /**
     * This method validates that the given password contains at least one character from each
     * of the following groups:
     * <ul>
     *   <li>Upper case letters</li>
     *   <li>Lower case letters</li>
     *   <li>Numbers</li>
     * </ul>
     * 
     * <p>If the validation condititions for this method are satisfied than the method will quietly
     * exit; if at least one condition is not satisfied than this method will throw an exception.
     * </p>
     *
     * @param password The password to be validated.
     *
     * @throws PasswordPolicyException On verification failure.
     */
    private void checkPasswordCharSet(String password)
        throws PasswordPolicyException
    {
        //Create some flags that will track that at least one character from each of the required
        //groups has been found in the provided password.
        boolean containsUpperChar = false;
        boolean containsLowerChar = false;
        boolean containsNumber = false;
        
        int length = password.length();
        for(int charCntr = 0; charCntr < length; charCntr++)
        {
            //Retrieve the current character and compare it to the different groups we're tracking.
            //If the character belongs to one of the groups we'll set the appropriate flag to 
            //true.
            char currChar = password.charAt(charCntr);
            if(('A' <= currChar) && (currChar <= 'Z'))
            {
                containsUpperChar = true;
                
            }  //end if statement
            else if(('a' <= currChar) && (currChar <= 'z'))
            {
                containsLowerChar = true;                
                
            }  //end else if statement
            else if(('0' <= currChar) && (currChar <= '9'))
            {
                containsNumber = true;
                
            }  //end else if statement            
            
        }  //end for loop        
        
        //Verify that the boolean flags for all groups are true; if not we'll throw a 
        //'PasswordPolicyException'.
        if((!containsUpperChar) || (!containsLowerChar) || (!containsNumber))
        {
            throw new PasswordPolicyException("All passwords must contain at least one of the " +
                                              "following: (1) Upper case letter, (2) lower " +
                "case letter, (3) a numeral.",
                5 );// 5 == PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY
            
        }  //end if statement
    
    }  //end method checkPasswordCharSet()
    
    
    /**
     * This method will assert that the given 'password' does not contain occurrances of the
     * same character 3 or more times in sequence.  If the check passes than the method will 
     * quietly exit; otherwise the method will throw an exception.
     *
     * @param password The password to be validated.
     *
     * @throws PasswordPolicyException On verification failure.
     */
    private void checkSequentialCharacterOccurrences(String password)
        throws PasswordPolicyException
    {
        //Verify that the password does not contain sequential occurrences of the same character
        //3 or more times.
        int passwordLength = password.length();
        for(int passwordCntr = 0; passwordCntr < (passwordLength - 2); passwordCntr++)
        {
            char currChar = password.charAt(passwordCntr);
            char nextChar = password.charAt(passwordCntr + 1);
            char lastChar = password.charAt(passwordCntr + 2);
            
            if((currChar == nextChar) && (currChar == lastChar))
            {
                throw new PasswordPolicyException("Occurrences of a single character must " +
                                                  "not appear 3 or more times in sequence.",
                    5 );// 5 == PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY                     
        
            }  //end if statement
            
        }  //end for loop
        
    }  //end method checkSequentialCharacterOccurrences(String)
    
    
    /**
     * This method will check a given password for mirrored sequences.  A "mirrored sequence" is
     * one where some sequence of characters is immediately followed by its inverse.  For example
     * "3RvR3" and "3RvvR3" are both mirrored sequences.  If a mirrored sequence is detected in the
     * provided 'password' than an exception will be thrown; otherwise this method will quietly
     * exit.
     *
     * @param password The password to be validated.
     *
     * @throws PasswordPolicyException On verification failure.
     */
    private void checkForMirroredSequences(String password)
        throws PasswordPolicyException
    {
        //Begin a scan of the 'password' given for any sequence that matches one of the following
        //descriptions; if a match is made it means that a mirror was found.
        //
        // 1). The character infront of the current character cursor is the same as the character
        //     behind it.
        //
        // 2). The character infront of the current charactor cursor is the same as the character
        //     pointed to by the cursor AND the character 2 places in front of the cursor is 
        //     the same as the character behind the cursor.
        //
        int passwordLength = password.length();
        for(int characterCursor = 1; characterCursor < (passwordLength - 1); characterCursor++)
        {
            if(password.charAt(characterCursor - 1) == (password.charAt(characterCursor + 1)))
            {
                throw new PasswordPolicyException("The password given was found to contain a " +
                                                  "sequence mirror.  Policy forbids the use of " +
                    "sequences in a password that combine a sequence with its reverse.  This " +
                    "restriction includes mirrors of all lengths but excludes duplicate " +
                    "characters.  Examples of mirrored sequences include 'ada' and 'nppn'.",
                    5 );// 5 == PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY
                
            }  //end if statement
            
            //Only test for mirrors of length 4 if at least 2 characters remain in front of the 
            //character cursor.
            if((passwordLength - 3) > characterCursor)
            {
                if((password.charAt(characterCursor) == password.charAt(characterCursor + 1)) &&
                   (password.charAt(characterCursor - 1) == (password.charAt(characterCursor + 2))))
                {
                    throw new PasswordPolicyException("The password given was found to contain " +
                                                      "a sequence mirror.  Policy forbids the " +
                        "use of sequences in a password that combine a sequence with its " +
                        "reverse.  This restriction includes mirrors of all lengths but excludes " +
                        "duplicate characters.  Examples of mirrored sequences include 'ada' and " +
                        "'nppn'.",
                        5 );// 5 == PasswordPolicyErrorEnum.INSUFFICIENT_PASSWORD_QUALITY
                    
                }  //end if statement
            
            }  //end if statement
            
        }  //end for loop
        
    }  //end method checkForMirroredSequences(String)
    
}
