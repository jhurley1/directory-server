/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.server.kerberos.shared.store;


import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.SamType;


public class PrincipalStoreEntryModifier
{
    // principal
    private String commonName;
    private KerberosPrincipal principal;
    private String realmName;

    // uidObject
    private String userId;

    // KDCEntry
    // must
    private int keyVersionNumber;
    // may
    private KerberosTime validStart;
    private KerberosTime validEnd;
    private KerberosTime passwordEnd;
    private int maxLife;
    private int maxRenew;
    private int kdcFlags;
    private int encryptionType;
    private SamType samType;
    private byte[] key;
    private boolean disabled = false;
    private boolean lockedOut = false;
    private KerberosTime expiration = KerberosTime.INFINITY;


    public PrincipalStoreEntry getEntry()
    {
        return new PrincipalStoreEntry( commonName, userId, principal, keyVersionNumber, validStart, validEnd,
            passwordEnd, maxLife, maxRenew, kdcFlags, encryptionType, key, realmName, samType, 
            disabled, lockedOut, expiration );
    }

    
    public void setDisabled( boolean disabled )
    {
        this.disabled = disabled;
    }
    
    
    public void setLockedOut( boolean lockedOut )
    {
        this.lockedOut = lockedOut;
    }
    
    
    public void setExpiration( KerberosTime expiration )
    {
        this.expiration = expiration;
    }

    
    public void setCommonName( String commonName )
    {
        this.commonName = commonName;
    }


    public void setUserId( String userId )
    {
        this.userId = userId;
    }


    public void setEncryptionType( int encryptionType )
    {
        this.encryptionType = encryptionType;
    }


    public void setKDCFlags( int kdcFlags )
    {
        this.kdcFlags = kdcFlags;
    }


    public void setKey( byte[] key )
    {
        this.key = key;
    }


    public void setKeyVersionNumber( int keyVersionNumber )
    {
        this.keyVersionNumber = keyVersionNumber;
    }


    public void setMaxLife( int maxLife )
    {
        this.maxLife = maxLife;
    }


    public void setMaxRenew( int maxRenew )
    {
        this.maxRenew = maxRenew;
    }


    public void setPasswordEnd( KerberosTime passwordEnd )
    {
        this.passwordEnd = passwordEnd;
    }


    public void setPrincipal( KerberosPrincipal principal )
    {
        this.principal = principal;
    }


    public void setRealmName( String realmName )
    {
        this.realmName = realmName;
    }


    public void setValidEnd( KerberosTime validEnd )
    {
        this.validEnd = validEnd;
    }


    public void setValidStart( KerberosTime validStart )
    {
        this.validStart = validStart;
    }


    public void setSamType( SamType samType )
    {
        this.samType = samType;
    }
}
