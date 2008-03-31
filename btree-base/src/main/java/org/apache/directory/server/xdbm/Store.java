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
package org.apache.directory.server.xdbm;


import org.apache.directory.server.schema.registries.OidRegistry;
import org.apache.directory.server.schema.registries.AttributeTypeRegistry;
import org.apache.directory.server.schema.registries.Registries;
import org.apache.directory.server.core.cursor.Cursor;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.name.Rdn;
import org.apache.directory.shared.ldap.entry.ModificationOperation;
import org.apache.directory.shared.ldap.entry.Modification;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.io.File;
import java.util.Set;
import java.util.Iterator;
import java.util.List;


/**
 * Represents an entry store based on the Table, Index, and MasterTable
 * database structure.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $$Rev$$
 */
public interface Store<E>
{
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.1) for apacheNdn op attrib */
    String NDN = "1.3.6.1.4.1.18060.0.4.1.2.1";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.2) for apacheUpdn op attrib */
    String UPDN = "1.3.6.1.4.1.18060.0.4.1.2.2";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.5) for apacheOneAlias index */
    String ONEALIAS = "1.3.6.1.4.1.18060.0.4.1.2.5";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.6) for apacheSubAlias index */
    String SUBALIAS = "1.3.6.1.4.1.18060.0.4.1.2.6";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.7) for apacheAlias index */
    String ALIAS = "1.3.6.1.4.1.18060.0.4.1.2.7";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.43) for apacheSubLevel index*/
    String SUBLEVEL = "1.3.6.1.4.1.18060.0.4.1.2.43";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.3) for apachePresence op attrib */
    String PRESENCE = "1.3.6.1.4.1.18060.0.4.1.2.3";
    /** Private OID (1.3.6.1.4.1.18060.0.4.1.2.4) for apacheOneLevel op attrib */
    String ONELEVEL = "1.3.6.1.4.1.18060.0.4.1.2.4";

    /*
     * W H Y   H A V E   A   S T O R E   I N T E R F A C E  ?
     * ------------------------------------------------------
     *
     * Some may question why we have this Store interface when the Partition
     * interface abstracts away partition implementation details in the server
     * core.  This is due to a complicated chicken and egg problem with the
     * additional need to abstract stores for the SearchEngine.  This way the
     * SearchEngine and it's default implementation can be independent of the
     * Partition interface.  Once this is achieved the default SearchEngine
     * implementation can be removed from the core.  This will allow for
     * better modularization, with the ability to easily substitute new
     * SearchEngine implementations into ApacheDS.
     *
     *
     * H I S T O R Y
     * -------------
     *
     * Originally the JdbmStore class came about due to a cyclic dependency.
     * The bootstrap-partition module is created by the bootstrap-plugin
     * module.  The core depends on the bootstrap-partition module to
     * bootstrap the server.  The bootstrap-partition module depends on the
     * bootstrap-plugin which builds a JdbmStore stuffing it with all the
     * information needed for the server to bootstrap.  The bootstrap-plugin
     * hence must be built before it can generate the bootstrap-partition and
     * it cannot have a dependency on the core.  We could not use the
     * JdbmPartition because it depends on the Partition interface and this
     * is an integral part of the core.  If we did then there would be a
     * cyclic dependency between modules in the apacheds pom.  To avoid this
     * the JdbmStore class was created and the guts of the JDBM partition were
     * put into the jdbm-store module.  This jdbm-store module does not depend
     * on core and can be used by the bootstrap-plugin to build the
     * bootstrap-partition.
     *
     * Hence it's project dependencies that drove the creation of the
     * JdbmStore class.  Later we realized, the default SeachEngine used by
     * all Table, Index, MasterTable scheme based partitions depends on
     * BTreePartition which depends on Partition.  We would like to remove
     * this search engine out of the core so it can easily be swapped out,
     * but most importantly so we can have the search depend on any kind of
     * store.  There's no reason why the SearchEngine should depend on a
     * Partition (store with search capabilities) when it just needs a simple
     * store and it's indices to conduct search operations.
     */


    void setWorkingDirectory( File workingDirectory );


    File getWorkingDirectory();


    void setUserIndices( Set<Index<?,E>> userIndices );


    Set<Index> getUserIndices();


    void setContextEntry( ServerEntry contextEntry );


    ServerEntry getContextEntry();


    void setSuffixDn( String suffixDn );


    String getSuffixDn();


    void setSyncOnWrite( boolean isSyncOnWrite );


    boolean isSyncOnWrite();


    void setCacheSize( int cacheSize );


    int getCacheSize();


    void setName( String name );


    String getName();


    /**
     * Initialize the JDBM storage system.
     *
     * @param oidRegistry an OID registry to resolve numeric identifiers from names
     * @param attributeTypeRegistry an attributeType specification registry to lookup type specs
     * @throws javax.naming.NamingException on failure to lookup elements in registries
     * @throws Exception on failure to create database files
     */
    void init( OidRegistry oidRegistry, AttributeTypeRegistry attributeTypeRegistry )
            throws Exception;


    /**
     * Close the parttion : we have to close all the userIndices and the master table.
     *
     * @throws Exception lazily thrown on any closer failures to avoid leaving
     * open files
     */
    void destroy() throws Exception;


    /**
     * Gets whether the store is initialized.
     *
     * @return true if the partition store is initialized
     */
    boolean isInitialized();


    /**
     * This method is called when the synch thread is waking up, to write
     * the modified data.
     *
     * @throws Exception on failures to sync database files to disk
     */
    void sync() throws Exception;


    void addIndex( Index index ) throws NamingException;


    Index<String,E> getPresenceIndex();


    void setPresenceIndex( Index<String,E> index ) throws NamingException;


    Index<Long,E> getOneLevelIndex();


    void setOneLevelIndex( Index<Long,E> index ) throws NamingException;


    Index<Long,E> getSubLevelIndex();


    void setSubLevelIndex( Index<Long,E> index ) throws NamingException;


    Index<String,E> getAliasIndex();


    void setAliasIndex( Index<String,E> index ) throws NamingException;


    Index<Long,E> getOneAliasIndex();


    void setOneAliasIndex( Index<Long,E> index ) throws NamingException;


    Index<Long,E> getSubAliasIndex();


    void setSubAliasIndex( Index<Long,E> index ) throws NamingException;


    Index<String,E> getUpdnIndex();


    void setUpdnIndex( Index<String,E> index ) throws NamingException;


    Index<String,E> getNdnIndex();


    void setNdnIndex( Index<String,E> index ) throws NamingException;


    Iterator<String> userIndices();


    Iterator<String> systemIndices();


    boolean hasUserIndexOn( String id ) throws NamingException;


    boolean hasSystemIndexOn( String id ) throws NamingException;


    Index getUserIndex( String id ) throws IndexNotFoundException;


    Index getSystemIndex( String id ) throws IndexNotFoundException;


    Long getEntryId( String dn ) throws Exception;


    String getEntryDn( Long id ) throws Exception;


    /**
     * Gets the Long id of an entry's parent using the child entry's
     * normalized dn. Note that the suffix entry returns 0, which does not
     * map to any entry.
     *
     * @param dn the normalized distinguished name of the child
     * @return the id of the parent entry or zero if the suffix entry the
     * normalized suffix dn string is used
     * @throws Exception on failures to access the underlying store
     */
    Long getParentId( String dn ) throws Exception;


    Long getParentId( Long childId ) throws Exception;


    String getEntryUpdn( Long id ) throws Exception;


    String getEntryUpdn( String dn ) throws Exception;


    int count() throws Exception;


    void add( LdapDN normName, Attributes entry ) throws Exception;


    Attributes lookup( Long id ) throws Exception;


    void delete( Long id ) throws Exception;


    /**
     * Gets an IndexEntry Cursor over the child nodes of an entry.
     *
     * @param id the id of the parent entry
     * @return an IndexEntry Cursor over the child entries
     * @throws Exception on failures to access the underlying store
     */
    Cursor<IndexEntry<Long,E>> list( Long id ) throws Exception;


    int getChildCount( Long id ) throws Exception;


    LdapDN getSuffix();


    LdapDN getUpSuffix();


    Attributes getSuffixEntry() throws Exception;


    void setProperty( String propertyName, String propertyValue ) throws Exception;


    String getProperty( String propertyName ) throws Exception;


    void modify( LdapDN dn, ModificationOperation modOp, ServerEntry mods ) throws Exception;


    void modify( LdapDN dn, List<Modification> mods ) throws Exception;


    /**
     * Changes the relative distinguished name of an entry specified by a
     * distinguished name with the optional removal of the old Rdn attribute
     * value from the entry.  Name changes propagate down as dn changes to the
     * descendants of the entry where the Rdn changed.
     *
     * An Rdn change operation does not change parent child relationships.  It
     * merely propagates a name change at a point in the DIT where the Rdn is
     * changed. The change propagates down the subtree rooted at the
     * distinguished name specified.
     *
     * @param dn the normalized distinguished name of the entry to alter
     * @param newRdn the new Rdn to set
     * @param deleteOldRdn whether or not to remove the old Rdn attr/val
     * @throws Exception if there are any errors propagating the name changes
     */
    void rename( LdapDN dn, Rdn newRdn, boolean deleteOldRdn ) throws Exception;


    void move( LdapDN oldChildDn, LdapDN newParentDn, Rdn newRdn, boolean deleteOldRdn ) throws Exception;


    void move( LdapDN oldChildDn, LdapDN newParentDn ) throws Exception;


    void initRegistries( Registries registries );
}
