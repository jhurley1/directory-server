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
package org.apache.directory.server;


import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InvalidAttributeIdentifierException;
import javax.naming.directory.InvalidAttributeValueException;
import javax.naming.directory.NoSuchAttributeException;
import javax.naming.directory.SchemaViolationException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.directory.server.unit.AbstractServerTest;
import org.apache.directory.shared.ldap.message.LockableAttributeImpl;
import org.apache.directory.shared.ldap.message.LockableAttributesImpl;
import org.apache.directory.shared.ldap.message.ModificationItemImpl;


/**
 * Testcase with different modify operations on a person entry. Each includes a
 * single removal op only.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class ModifyRemoveTest extends AbstractServerTest
{

    private LdapContext ctx = null;

    public static final String RDN = "cn=Tori Amos";


    /**
     * Creation of required attributes of a person entry.
     */
    protected Attributes getPersonAttributes( String sn, String cn )
    {
        Attributes attributes = new LockableAttributesImpl();
        Attribute attribute = new LockableAttributeImpl( "objectClass" );
        attribute.add( "top" );
        attribute.add( "person" );
        attributes.put( attribute );
        attributes.put( "cn", cn );
        attributes.put( "sn", sn );

        return attributes;
    }


    /**
     * Creation of required attributes of an inetOrgPerson entry.
     */
    protected Attributes getInetOrgPersonAttributes( String sn, String cn )
    {
        Attributes attrs = new LockableAttributesImpl();
        Attribute ocls = new LockableAttributeImpl( "objectClass" );
        ocls.add( "top" );
        ocls.add( "person" );
        ocls.add( "organizationalPerson" );
        ocls.add( "inetOrgPerson" );
        attrs.put( ocls );
        attrs.put( "cn", cn );
        attrs.put( "sn", sn );

        return attrs;
    }


    /**
     * Create context and a person entry.
     */
    public void setUp() throws Exception
    {
        super.setUp();

        Hashtable env = new Hashtable();
        env.put( "java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory" );
        env.put( "java.naming.provider.url", "ldap://localhost:" + port + "/ou=system" );
        env.put( "java.naming.security.principal", "uid=admin,ou=system" );
        env.put( "java.naming.security.credentials", "secret" );
        env.put( "java.naming.security.authentication", "simple" );

        ctx = new InitialLdapContext( env, null );
        assertNotNull( ctx );

        // Create a person with description
        Attributes attributes = this.getPersonAttributes( "Amos", "Tori Amos" );
        attributes.put( "description", "an American singer-songwriter" );
        ctx.createSubcontext( RDN, attributes );

    }


    /**
     * Remove person entry and close context.
     */
    public void tearDown() throws Exception
    {
        ctx.unbind( RDN );
        ctx.close();
        ctx = null;
        super.tearDown();
    }


    /**
     * Just a little test to check wether opening the connection and creation of
     * the person succeeds succeeds.
     */
    public void testSetUpTearDown() throws NamingException
    {
        assertNotNull( ctx );
        DirContext tori = ( DirContext ) ctx.lookup( RDN );
        assertNotNull( tori );
    }


    /**
     * Remove an attribute, which is not required.
     * 
     * Expected result: After successful deletion, attribute is not present in
     * entry.
     * 
     * @throws NamingException
     */
    public void testRemoveNotRequiredAttribute() throws NamingException
    {
        // Remove description Attribute
        Attribute attr = new LockableAttributeImpl( "description" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );
        ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );

        // Verify, that attribute is deleted
        attrs = ctx.getAttributes( RDN );
        attr = attrs.get( "description" );
        assertNull( attr );
    }


    /**
     * Remove two not required attributes.
     * 
     * Expected result: After successful deletion, both attributes ar not
     * present in entry.
     * 
     * @throws NamingException
     */
    public void testRemoveTwoNotRequiredAttributes() throws NamingException
    {
        // add telephoneNumber to entry
        Attributes tn = new LockableAttributesImpl( "telephoneNumber", "12345678" );
        ctx.modifyAttributes( RDN, DirContext.ADD_ATTRIBUTE, tn );

        // Remove description and telephoneNumber to Attribute
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( new LockableAttributeImpl( "description" ) );
        attrs.put( new LockableAttributeImpl( "telephoneNumber" ) );
        ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );

        // Verify, that attributes are deleted
        attrs = ctx.getAttributes( RDN );
        assertNull( attrs.get( "description" ) );
        assertNull( attrs.get( "telephoneNumber" ) );
        assertNotNull( attrs.get( "cn" ) );
        assertNotNull( attrs.get( "sn" ) );
    }


    /**
     * Remove a required attribute. The sn attribute of the person entry is used
     * here.
     * 
     * Expected Result: Deletion fails with NamingException (Schema Violation).
     * 
     * @throws NamingException
     */
    public void testRemoveRequiredAttribute() throws NamingException
    {
        // Remove sn attribute
        Attribute attr = new LockableAttributeImpl( "sn" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );

        try
        {
            ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );
            fail( "Deletion of required attribute should fail." );
        }
        catch ( SchemaViolationException e )
        {
            // expected behaviour
        }
    }


    /**
     * Remove a required attribute from RDN.
     * 
     * Expected Result: Deletion fails with SchemaViolationException.
     * 
     * @throws NamingException
     */
    public void testRemovePartOfRdn() throws NamingException
    {
        // Remove sn attribute
        Attribute attr = new LockableAttributeImpl( "cn" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );

        try
        {
            ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );
            fail( "Deletion of RDN attribute should fail." );
        }
        catch ( SchemaViolationException e )
        {
            // expected behaviour
        }
    }


    /**
     * Remove a not required attribute from RDN.
     * 
     * Expected Result: Deletion fails with SchemaViolationException.
     * 
     * @throws NamingException
     */
    public void testRemovePartOfRdnNotRequired() throws NamingException
    {
        // Change RDN to another attribute
        String newRdn = "description=an American singer-songwriter";
        ctx.addToEnvironment( "java.naming.ldap.deleteRDN", "false" );
        ctx.rename( RDN, newRdn );

        // Remove description, which is now RDN attribute
        Attribute attr = new LockableAttributeImpl( "description" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );

        try
        {
            ctx.modifyAttributes( newRdn, DirContext.REMOVE_ATTRIBUTE, attrs );
            fail( "Deletion of RDN attribute should fail." );
        }
        catch ( SchemaViolationException e )
        {
            // expected behaviour
        }

        // Change RDN back to original
        ctx.addToEnvironment( "java.naming.ldap.deleteRDN", "false" );
        ctx.rename( newRdn, RDN );
    }


    /**
     * Remove a an attribute which is not present on the entry, but in the
     * schema.
     * 
     * Expected result: Deletion fails with NoSuchAttributeException
     * 
     * @throws NamingException
     */
    public void testRemoveAttributeNotPresent() throws NamingException
    {
        // Remove telephoneNumber Attribute
        Attribute attr = new LockableAttributeImpl( "telephoneNumber" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );

        try
        {
            ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );
            fail( "Deletion of attribute, which is not present in the entry, should fail." );
        }
        catch ( NoSuchAttributeException e )
        {
            // expected behaviour
        }
    }


    /**
     * Remove a an attribute which is not present in the schema.
     * 
     * Expected result: Deletion fails with NoSuchAttributeException
     * 
     * @throws NamingException
     */
    public void testRemoveAttributeNotValid() throws NamingException
    {
        // Remove phantasy attribute
        Attribute attr = new LockableAttributeImpl( "XXX" );
        Attributes attrs = new LockableAttributesImpl();
        attrs.put( attr );

        try
        {
            ctx.modifyAttributes( RDN, DirContext.REMOVE_ATTRIBUTE, attrs );
            fail( "Deletion of an invalid attribute should fail." );
        }
        catch ( NoSuchAttributeException e )
        {
            // expected behaviour
        }
        catch ( InvalidAttributeIdentifierException e )
        {
            // expected behaviour
        }
    }


    /**
     * Create a person entry and try to remove an attribute value
     */
    public void testReplaceNonExistingAttribute() throws NamingException
    {
        // Create an entry
        Attributes attrs = getInetOrgPersonAttributes( "Bush", "Kate Bush" );
        attrs.put( "givenname", "Kate" );
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext( rdn, attrs );

        // replace attribute givenName with empty value (=> deletion)
        Attribute attr = new LockableAttributeImpl( "givenname" );
        ModificationItemImpl item = new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, attr );
        ctx.modifyAttributes( rdn, new ModificationItemImpl[] { item } );

        SearchControls sctls = new SearchControls();
        sctls.setSearchScope( SearchControls.ONELEVEL_SCOPE );
        String filter = "(cn=Kate Bush)";
        String base = "";
        NamingEnumeration enm = ctx.search( base, filter, sctls );
        if ( enm.hasMore() )
        {
            SearchResult sr = ( SearchResult ) enm.next();
            attrs = sr.getAttributes();
            Attribute cn = sr.getAttributes().get( "cn" );
            assertNotNull( cn );
            assertTrue( cn.contains( "Kate Bush" ) );

            // Check whether attribute has been removed
            Attribute givenName = sr.getAttributes().get( "givenname" );
            assertNull( givenName );
        }
        else
        {
            fail( "entry not found" );
        }

        ctx.destroySubcontext( rdn );
    }


    /**
     * Create a person entry and try to remove an attribute value from the RDN
     * by Replacement
     */
    public void testReplaceRdnByEmptyValueAttribute() throws NamingException
    {

        // Create an entry
        Attributes attrs = getPersonAttributes( "Bush", "Kate Bush" );
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext( rdn, attrs );

        // replace attribute cn with empty value (=> deletion)
        Attribute attr = new LockableAttributeImpl( "cn" );
        ModificationItemImpl item = new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, attr );

        try
        {
            ctx.modifyAttributes( rdn, new ModificationItemImpl[]
                { item } );
            fail( "modify should fail" );
        }
        catch ( SchemaViolationException e )
        {
            // Expected behaviour
        }

        ctx.destroySubcontext( rdn );
    }


    /**
     * Create a person entry and try to remove an attribute from the RDN
     */
    public void testRemoveRdnAttribute() throws NamingException
    {

        // Create an entry
        Attributes attrs = getPersonAttributes( "Bush", "Kate Bush" );
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext( rdn, attrs );

        // replace attribute cn with empty value (=> deletion)
        Attribute attr = new LockableAttributeImpl( "cn" );
        ModificationItemImpl item = new ModificationItemImpl( DirContext.REMOVE_ATTRIBUTE, attr );

        try
        {
            ctx.modifyAttributes( rdn, new ModificationItemImpl[]
                { item } );
            fail( "modify should fail" );
        }
        catch ( SchemaViolationException e )
        {
            // Expected behaviour
        }

        ctx.destroySubcontext( rdn );
    }


    /**
     * Create a person entry and try to remove an attribute from the RDN
     */
    public void testRemoveRdnAttributeValue() throws NamingException
    {

        // Create an entry
        Attributes attrs = getPersonAttributes( "Bush", "Kate Bush" );
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext( rdn, attrs );

        // replace attribute cn with empty value (=> deletion)
        Attribute attr = new LockableAttributeImpl( "cn", "Kate Bush" );
        ModificationItemImpl item = new ModificationItemImpl( DirContext.REMOVE_ATTRIBUTE, attr );

        try
        {
            ctx.modifyAttributes( rdn, new ModificationItemImpl[]
                { item } );
            fail( "modify should fail" );
        }
        catch ( SchemaViolationException e )
        {
            // Expected behaviour
        }

        ctx.destroySubcontext( rdn );
    }
    
    /**
     * Create a person entry and try to remove objectClass attribute
     */
    public void testDeleteOclAttrWithTopPersonOrganizationalpersonInetorgperson() throws NamingException {

        // Create an entry
        Attributes attrs = getInetOrgPersonAttributes("Bush", "Kate Bush");
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext(rdn, attrs);

        ModificationItemImpl delModOp = new ModificationItemImpl(DirContext.REMOVE_ATTRIBUTE, new LockableAttributeImpl("objectclass", ""));

        try {
            ctx.modifyAttributes(rdn, new ModificationItemImpl[] { delModOp });
            fail("deletion of objectclass should fail");
        } catch (SchemaViolationException e) {
            // expected
        } catch (NoSuchAttributeException e) {
            // expected
        } catch (InvalidAttributeValueException e) {
            // expected
        }

        ctx.destroySubcontext(rdn);
    }

    /**
     * Create a person entry and try to remove objectClass attribute. A variant
     * which works.
     */
    public void testDeleteOclAttrWithTopPersonOrganizationalpersonInetorgpersonVariant() throws NamingException {

        // Create an entry
        Attributes attrs = getInetOrgPersonAttributes("Bush", "Kate Bush");
        String rdn = "cn=Kate Bush";
        ctx.createSubcontext(rdn, attrs);

        ModificationItemImpl delModOp = new ModificationItemImpl(DirContext.REMOVE_ATTRIBUTE, new LockableAttributeImpl("objectclass"));

        try {
            ctx.modifyAttributes(rdn, new ModificationItemImpl[] { delModOp });
            fail("deletion of objectclass should fail");
        } catch (SchemaViolationException e) {
            // expected
        }

        ctx.destroySubcontext(rdn);
    }
}
