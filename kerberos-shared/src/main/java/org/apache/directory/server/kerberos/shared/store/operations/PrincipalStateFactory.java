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

package org.apache.directory.server.kerberos.shared.store.operations;


import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SchemaViolationException;
import javax.naming.spi.DirStateFactory;

import org.apache.directory.server.kerberos.shared.store.KerberosAttribute;
import org.apache.directory.server.kerberos.shared.store.PrincipalStoreEntry;
import org.apache.directory.shared.ldap.message.LockableAttributeImpl;
import org.apache.directory.shared.ldap.message.LockableAttributesImpl;
import org.apache.directory.shared.ldap.util.AttributeUtils;


/**
 * A StateFactory for a server profile.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PrincipalStateFactory implements DirStateFactory
{
    public Result getStateToBind( Object obj, Name name, Context nameCtx, Hashtable environment, Attributes inAttrs )
        throws NamingException
    {
        // Only interested in PrincipalStoreEntry objects
        if ( obj instanceof PrincipalStoreEntry )
        {
            Attributes outAttrs;
            if ( inAttrs == null )
            {
                outAttrs = new LockableAttributesImpl( true );
            }
            else
            {
                outAttrs = ( Attributes ) inAttrs.clone();
            }

            // process the objectClass attribute
            Attribute oc = outAttrs.get( "objectClass" );

            if ( oc == null )
            {
                oc = new LockableAttributeImpl( "objectClass" );
                outAttrs.put( oc );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "top" ) )
            {
                oc.add( "top" );
            }

            PrincipalStoreEntry p = ( PrincipalStoreEntry ) obj;

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "uidObject" ) )
            {
                oc.add( "uidObject" );
                if ( p.getUserId() != null )
                {
                    outAttrs.put( "uid", p.getUserId() );
                }
                else
                {
                    throw new SchemaViolationException( "Person must have uid." );
                }
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "extensibleObject" ) )
            {
                oc.add( "extensibleObject" );
                outAttrs.put( "apacheSamType", "7" );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "person" ) )
            {
                oc.add( "person" );

                // TODO - look into adding sn, gn, and cn to ServerProfiles
                outAttrs.put( "sn", p.getUserId() );
                outAttrs.put( "cn", p.getCommonName() );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "organizationalPerson" ) )
            {
                oc.add( "organizationalPerson" );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "inetOrgPerson" ) )
            {
                oc.add( "inetOrgPerson" );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "krb5Principal" ) )
            {
                oc.add( "krb5Principal" );
            }

            if ( !AttributeUtils.containsValueCaseIgnore( oc, "krb5KDCEntry" ) )
            {
                oc.add( "krb5KDCEntry" );

                String principal = p.getPrincipal().getName();
                byte[] keyBytes = p.getEncryptionKey().getKeyValue();
                int keyType = p.getEncryptionKey().getKeyType().getOrdinal();
                int keyVersion = p.getEncryptionKey().getKeyVersion();

                outAttrs.put( KerberosAttribute.PRINCIPAL, principal );
                outAttrs.put( KerberosAttribute.KEY, keyBytes );
                outAttrs.put( KerberosAttribute.TYPE, Integer.toString( keyType ) );
                outAttrs.put( KerberosAttribute.VERSION, Integer.toString( keyVersion ) );
            }

            Result r = new Result( obj, outAttrs );

            System.out.println( "Result from obj " + obj );
            System.out.println( "Result attrs " + outAttrs );

            return r;
        }

        System.out.println( "ERROR:  entry was not correct type " + obj );
        return null;
    }


    public Object getStateToBind( Object obj, Name name, Context nameCtx, Hashtable environment )
        throws NamingException
    {
        throw new UnsupportedOperationException( "Structural objectClass needed with additional attributes!" );
    }
}
