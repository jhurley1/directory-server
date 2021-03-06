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
package org.apache.directory.server.kerberos.shared.messages.components;


import org.apache.directory.server.kerberos.shared.messages.value.HostAddress;
import org.apache.directory.server.kerberos.shared.messages.value.HostAddresses;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.KrbCredInfo;


/**
 * Encrypted part of credential message types
 */
public class EncKrbCredPart
{
    public KrbCredInfo[] ticketInfo;
    public Integer nonce; //optional
    public KerberosTime timeStamp; //optional
    public Integer usec; //optional
    public HostAddress sAddress; //optional
    public HostAddresses rAddress; //optional


    /**
     * Class constructor
     */
    public EncKrbCredPart(KrbCredInfo[] ticketInfo, KerberosTime timeStamp, Integer usec, Integer nonce,
        HostAddress sAddress, HostAddresses rAddress)
    {
        this.ticketInfo = ticketInfo;
        this.nonce = nonce;
        this.timeStamp = timeStamp;
        this.usec = usec;
        this.sAddress = sAddress;
        this.rAddress = rAddress;
    }
}
