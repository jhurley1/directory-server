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
package org.apache.directory.server.kerberos.shared.io.decoder;


import java.util.Enumeration;

import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.shared.asn1.der.DERInteger;
import org.apache.directory.shared.asn1.der.DERSequence;


public class EncryptionTypeDecoder
{
    /**
     * etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
     *             -- in preference order
     */
    protected static EncryptionType[] decode( DERSequence sequence )
    {
        EncryptionType[] eTypes = new EncryptionType[sequence.size()];

        int ii = 0;
        for ( Enumeration e = sequence.getObjects(); e.hasMoreElements(); )
        {
            DERInteger object = ( DERInteger ) e.nextElement();
            eTypes[ii] = EncryptionType.getTypeByOrdinal( object.intValue() );
            ii++;
        }

        return eTypes;
    }
}
