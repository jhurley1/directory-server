/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package org.apache.ldap.server.jndi;


import java.io.File;
import java.io.IOException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

import junit.framework.TestCase;
import org.apache.commons.io.FileUtils;
import org.apache.ldap.common.exception.LdapNoPermissionException;


/**
 * Testing RootDSE lookups and context creation using the empty string.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class RootDSETest extends TestCase
{
    /** flag whether to delete database files for each test or not */
    protected boolean doDelete = true;


    /**
     * Get's the initial context factory for the provider's ou=system context
     * root.
     *
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception
    {
        super.setUp();
        doDelete( new File( "target" + File.separator + "eve" ) );
    }


    /**
     * Deletes the Eve working directory.
     *
     * @throws java.io.IOException if there are failures while deleting.
     */
    protected void doDelete( File wkdir ) throws IOException
    {
        if ( doDelete )
        {
            if ( wkdir.exists() )
            {
                FileUtils.deleteDirectory( wkdir );
            }
        }
    }


    /**
     * Sets the system context root to null.
     *
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception
    {
        super.tearDown();
        Hashtable env = new Hashtable();
        env.put( Context.PROVIDER_URL, "ou=system" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, "org.apache.ldap.server.jndi.ServerContextFactory" );
        env.put( EnvKeys.SHUTDOWN, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        try { new InitialContext( env ); } catch( Exception e ) {}
    }


    /**
     * Creates an initial context using the empty string for the provider URL.
     * This should work.
     *
     * @throws NamingException if there are any problems
     */
    public void testGetInitialContext() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );
    }


    /**
     * Gets a DirContext from the InitialContext for the empty string or RootDSE
     * and checks that none of the operational attributes are returned.
     *
     * @throws NamingException if there are any problems
     */
    public void testGetInitialContextLookupAttributes() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );
        Attributes attributes = ctx.getAttributes( "" );

        // Added some objectClass attributes to the rootDSE
        assertEquals( 1, attributes.size() );
    }


    /**
     * Checks for namingContexts and vendorName attributes.
     *
     * @throws NamingException if there are any problems
     */
    public void testGetInitialContextLookupAttributesByName() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );
        Attributes attributes = ctx.getAttributes( "", new String[]{ "namingContexts", "vendorName" });
        assertEquals( 2, attributes.size() );
        assertEquals( "Apache Software Foundation", attributes.get( "vendorName" ).get() );
        assertTrue( attributes.get( "namingContexts" ).contains( "ou=system" ) );
    }


    /**
     * Checks for lack of permissions to delete this entry.
     *
     * @throws NamingException if there are any problems
     */
    public void testDelete() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );

        LdapNoPermissionException notNull = null;

        try
        {
            ctx.destroySubcontext( "" );
            fail( "we should never get here" );
        }
        catch ( LdapNoPermissionException e )
        {
            notNull = e;
        }

        assertNotNull( notNull );
    }


    /**
     * Checks for lack of permissions to rename or move this entry.
     *
     * @throws NamingException if there are any problems
     */
    public void testRename() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );

        LdapNoPermissionException notNull = null;

        try
        {
            ctx.rename( "", "ou=system" );
            fail( "we should never get here" );
        }
        catch ( LdapNoPermissionException e )
        {
            notNull = e;
        }

        assertNotNull( notNull );
    }


    /**
     * Checks for lack of permissions to modify this entry.
     *
     * @throws NamingException if there are any problems
     */
    public void testModify() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );

        LdapNoPermissionException notNull = null;

        try
        {
            ctx.modifyAttributes( "", 0, null );
            fail( "we should never get here" );
        }
        catch ( LdapNoPermissionException e )
        {
            notNull = e;
        }

        assertNotNull( notNull );
    }




    /**
     * Checks for lack of permissions to modify this entry.
     *
     * @throws NamingException if there are any problems
     */
    public void testModify2() throws NamingException
    {
        Hashtable env = new Hashtable();
        env.put( EnvKeys.WKDIR, "target/eve" );
        env.put( Context.PROVIDER_URL, "" );
        env.put( Context.SECURITY_PRINCIPAL, "uid=admin,ou=system" );
        env.put( Context.SECURITY_CREDENTIALS, "secret" );
        env.put( Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName() );
        InitialContext initCtx = new InitialContext( env );
        assertNotNull( initCtx );

        DirContext ctx = ( DirContext ) initCtx.lookup( "" );

        LdapNoPermissionException notNull = null;

        try
        {
            ctx.modifyAttributes( "", new ModificationItem[]{} );
            fail( "we should never get here" );
        }
        catch ( LdapNoPermissionException e )
        {
            notNull = e;
        }

        assertNotNull( notNull );
    }
}
