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
package org.apache.directory.server.core.schema;


import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.naming.NamingException;

import org.apache.directory.server.core.schema.bootstrap.BootstrapMatchingRuleUseRegistry;
import org.apache.directory.shared.ldap.schema.MatchingRuleUse;
import org.apache.directory.shared.ldap.util.JoinIterator;


/**
 * A plain old java object implementation of an MatchingRuleUseRegistry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class GlobalMatchingRuleUseRegistry implements MatchingRuleUseRegistry
{
    /** maps an OID to an MatchingRuleUse */
    private final Map byOid;
    /** maps an OID to a schema name*/
    private final Map oidToSchema;
    /** the registry used to resolve names to OIDs */
    private final OidRegistry oidRegistry;
    /** monitor notified via callback events */
    private MatchingRuleUseRegistryMonitor monitor;
    /** the underlying bootstrap registry to delegate on misses to */
    private BootstrapMatchingRuleUseRegistry bootstrap;


    // ------------------------------------------------------------------------
    // C O N S T R U C T O R S
    // ------------------------------------------------------------------------

    /**
     * Creates an empty BootstrapMatchingRuleUseRegistry.
     */
    public GlobalMatchingRuleUseRegistry(BootstrapMatchingRuleUseRegistry bootstrap, OidRegistry oidRegistry)
    {
        this.byOid = new HashMap();
        this.oidToSchema = new HashMap();
        this.oidRegistry = oidRegistry;
        this.monitor = new MatchingRuleUseRegistryMonitorAdapter();

        this.bootstrap = bootstrap;
        if ( this.bootstrap == null )
        {
            throw new NullPointerException( "the bootstrap registry cannot be null" );
        }
    }


    /**
     * Sets the monitor that is to be notified via callback events.
     *
     * @param monitor the new monitor to notify of notable events
     */
    public void setMonitor( MatchingRuleUseRegistryMonitor monitor )
    {
        this.monitor = monitor;
    }


    // ------------------------------------------------------------------------
    // Service Methods
    // ------------------------------------------------------------------------

    public void register( String schema, MatchingRuleUse dITContentRule ) throws NamingException
    {
        if ( byOid.containsKey( dITContentRule.getOid() ) || bootstrap.hasMatchingRuleUse( dITContentRule.getOid() ) )
        {
            NamingException e = new NamingException( "dITContentRule w/ OID " + dITContentRule.getOid()
                + " has already been registered!" );
            monitor.registerFailed( dITContentRule, e );
            throw e;
        }

        oidRegistry.register( dITContentRule.getName(), dITContentRule.getOid() );
        byOid.put( dITContentRule.getOid(), dITContentRule );
        oidToSchema.put( dITContentRule.getOid(), schema );
        monitor.registered( dITContentRule );
    }


    public MatchingRuleUse lookup( String id ) throws NamingException
    {
        id = oidRegistry.getOid( id );

        if ( byOid.containsKey( id ) )
        {
            MatchingRuleUse dITContentRule = ( MatchingRuleUse ) byOid.get( id );
            monitor.lookedUp( dITContentRule );
            return dITContentRule;
        }

        if ( bootstrap.hasMatchingRuleUse( id ) )
        {
            MatchingRuleUse dITContentRule = bootstrap.lookup( id );
            monitor.lookedUp( dITContentRule );
            return dITContentRule;
        }

        NamingException e = new NamingException( "dITContentRule w/ OID " + id + " not registered!" );
        monitor.lookupFailed( id, e );
        throw e;
    }


    public boolean hasMatchingRuleUse( String id )
    {
        if ( oidRegistry.hasOid( id ) )
        {
            try
            {
                return byOid.containsKey( oidRegistry.getOid( id ) ) || bootstrap.hasMatchingRuleUse( id );
            }
            catch ( NamingException e )
            {
                return false;
            }
        }

        return false;
    }


    public String getSchemaName( String id ) throws NamingException
    {
        id = oidRegistry.getOid( id );

        if ( oidToSchema.containsKey( id ) )
        {
            return ( String ) oidToSchema.get( id );
        }

        if ( bootstrap.hasMatchingRuleUse( id ) )
        {
            return bootstrap.getSchemaName( id );
        }

        throw new NamingException( "OID " + id + " not found in oid to " + "schema name map!" );
    }


    public Iterator list()
    {
        return new JoinIterator( new Iterator[]
            { byOid.values().iterator(), bootstrap.list() } );
    }
}
