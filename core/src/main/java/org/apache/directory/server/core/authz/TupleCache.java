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
package org.apache.directory.server.core.authz;


import java.text.ParseException;
import java.util.*;

import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.directory.server.core.DirectoryServiceConfiguration;
import org.apache.directory.server.core.partition.PartitionNexus;
import org.apache.directory.server.core.schema.AttributeTypeRegistry;
import org.apache.directory.server.core.schema.ConcreteNameComponentNormalizer;
import org.apache.directory.server.core.schema.OidRegistry;
import org.apache.directory.shared.ldap.aci.ACIItem;
import org.apache.directory.shared.ldap.aci.ACIItemParser;
import org.apache.directory.shared.ldap.exception.LdapSchemaViolationException;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.filter.SimpleNode;
import org.apache.directory.shared.ldap.message.ModificationItemImpl;
import org.apache.directory.shared.ldap.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.name.NameComponentNormalizer;
import org.apache.directory.shared.ldap.util.AttributeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A cache for tuple sets which responds to specific events to perform
 * cache house keeping as access control subentries are added, deleted
 * and modified.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class TupleCache
{
    /** the attribute id for prescriptive aci: prescriptiveACI */
    private static final String ACI_ATTR = "prescriptiveACI";
    /** the attribute id for an object class: objectClass */
    private static final String OC_ATTR = "objectClass";
    /** the object class for access control subentries: accessControlSubentry */
    private static final String ACSUBENTRY_OC = "accessControlSubentry";

    /** the logger for this class */
    private static final Logger log = LoggerFactory.getLogger( TupleCache.class );

    /** cloned startup environment properties we use for subentry searching */
    private final Hashtable env;
    /** a map of strings to ACITuple collections */
    private final Map tuples = new HashMap();
    /** a handle on the partition nexus */
    private final PartitionNexus nexus;
    /** a normalizing ACIItem parser */
    private final ACIItemParser aciParser;

    /**
     * The OIDs normalizer map
     */
    private Map normalizerMap;

    /**
     * Creates a ACITuple cache.
     *
     * @param factoryCfg the context factory configuration for the server
     */
    public TupleCache( DirectoryServiceConfiguration factoryCfg ) throws NamingException
    {
    	normalizerMap = factoryCfg.getGlobalRegistries().getAttributeTypeRegistry().getNormalizerMapping();
        this.nexus = factoryCfg.getPartitionNexus();
        AttributeTypeRegistry attributeRegistry = factoryCfg.getGlobalRegistries().getAttributeTypeRegistry();
        OidRegistry oidRegistry = factoryCfg.getGlobalRegistries().getOidRegistry();
        NameComponentNormalizer ncn = new ConcreteNameComponentNormalizer( attributeRegistry, oidRegistry );
        aciParser = new ACIItemParser( ncn, normalizerMap );
        env = ( Hashtable ) factoryCfg.getEnvironment().clone();
        initialize();
    }

    
    private LdapDN parseNormalized( String name ) throws NamingException
    {
        LdapDN dn = new LdapDN( name );
        dn.normalize( normalizerMap );
        return dn;
    }


    private void initialize() throws NamingException
    {
        // search all naming contexts for access control subentenries
        // generate ACITuple Arrays for each subentry
        // add that subentry to the hash
        Iterator suffixes = nexus.listSuffixes();
        while ( suffixes.hasNext() )
        {
            String suffix = ( String ) suffixes.next();
            LdapDN baseDn = parseNormalized( suffix );
            ExprNode filter = new SimpleNode( OC_ATTR, ACSUBENTRY_OC, SimpleNode.EQUALITY );
            SearchControls ctls = new SearchControls();
            ctls.setSearchScope( SearchControls.SUBTREE_SCOPE );
            NamingEnumeration results = nexus.search( baseDn, env, filter, ctls );
            while ( results.hasMore() )
            {
                SearchResult result = ( SearchResult ) results.next();
                String subentryDn = result.getName();
                Attribute aci = result.getAttributes().get( ACI_ATTR );
                if ( aci == null )
                {
                    log.warn( "Found accessControlSubentry '" + subentryDn + "' without any " + ACI_ATTR );
                    continue;
                }

                LdapDN normName = parseNormalized( subentryDn );
                subentryAdded( subentryDn, normName, result.getAttributes() );
            }
            results.close();
        }
    }


    private boolean hasPrescriptiveACI( Attributes entry ) throws NamingException
    {
        // only do something if the entry contains prescriptiveACI
        Attribute aci = entry.get( ACI_ATTR );
        
        if ( aci == null )
        {
            if ( AttributeUtils.containsValueCaseIgnore( entry.get( OC_ATTR ), ACSUBENTRY_OC ) )
            {
                // should not be necessary because of schema interceptor but schema checking
                // can be turned off and in this case we must protect against being able to
                // add access control information to anything other than an AC subentry
                throw new LdapSchemaViolationException( "", ResultCodeEnum.OBJECTCLASSVIOLATION );
            }
            else
            {
                return false;
            }
        }
        
        return true;
    }


    public void subentryAdded( String upName, LdapDN normName, Attributes entry ) throws NamingException
    {
        // only do something if the entry contains prescriptiveACI
        Attribute aci = entry.get( ACI_ATTR );
        if ( !hasPrescriptiveACI( entry ) )
        {
            return;
        }

        List entryTuples = new ArrayList();
        for ( int ii = 0; ii < aci.size(); ii++ )
        {
            ACIItem item = null;

            try
            {
                item = aciParser.parse( ( String ) aci.get( ii ) );
            }
            catch ( ParseException e )
            {
                String msg = "ACIItem parser failure on \n'" + item + "'\ndue to syntax error. " +
                        "Cannnot add ACITuples to TupleCache.\n" +
                        "Check that the syntax of the ACI item is correct. \nUntil this error " +
                        "is fixed your security settings will not be as expected.";
                log.error( msg, e );
                
                // do not process this ACI Item because it will be null
                // continue on to process the next ACI item in the entry
                continue;
            }

            entryTuples.addAll( item.toTuples() );
        }
        tuples.put( normName.toNormName(), entryTuples );
    }


    public void subentryDeleted( Name normName, Attributes entry ) throws NamingException
    {
        if ( !hasPrescriptiveACI( entry ) )
        {
            return;
        }

        tuples.remove( normName.toString() );
    }
    

    public void subentryModified( LdapDN normName, ModificationItemImpl[] mods, Attributes entry ) throws NamingException
    {
        if ( !hasPrescriptiveACI( entry ) )
        {
            return;
        }
        
        for ( int ii = 0; ii < mods.length; ii++ )
        {
            String attrID = mods[ii].getAttribute().getID();
            if ( attrID.equalsIgnoreCase( ACI_ATTR ) )
            {
                subentryDeleted( normName, entry );
                subentryAdded( normName.getUpName(), normName, entry );
                continue;
            }
        }
    }


    public void subentryModified( LdapDN normName, int modOp, Attributes mods, Attributes entry ) throws NamingException
    {
        if ( !hasPrescriptiveACI( entry ) )
        {
            return;
        }

        if ( mods.get( ACI_ATTR ) != null )
        {
            subentryDeleted( normName, entry );
            subentryAdded( normName.getUpName(), normName, entry );
        }
    }


    public List getACITuples( String subentryDn )
    {
        List aciTuples = ( List ) tuples.get( subentryDn );
        if ( aciTuples == null )
        {
            return Collections.EMPTY_LIST;
        }
        return Collections.unmodifiableList( aciTuples );
    }


    public void subentryRenamed( Name oldName, Name newName )
    {
        tuples.put( newName.toString(), tuples.remove( oldName.toString() ) );
    }
}
