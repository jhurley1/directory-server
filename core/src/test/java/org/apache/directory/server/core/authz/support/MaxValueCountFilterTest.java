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
package org.apache.directory.server.core.authz.support;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.apache.directory.server.core.authz.support.MaxValueCountFilter;
import org.apache.directory.server.core.authz.support.OperationScope;
import org.apache.directory.shared.ldap.aci.ACITuple;
import org.apache.directory.shared.ldap.aci.AuthenticationLevel;
import org.apache.directory.shared.ldap.aci.ProtectedItem;
import org.apache.directory.shared.ldap.aci.ProtectedItem.MaxValueCountItem;
import org.apache.directory.shared.ldap.message.LockableAttributeImpl;
import org.apache.directory.shared.ldap.message.LockableAttributesImpl;


/**
 * Tests {@link MaxValueCountFilter}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class MaxValueCountFilterTest extends TestCase
{
    private static final Collection EMPTY_COLLECTION = Collections.unmodifiableCollection( new ArrayList() );
    private static final Set EMPTY_SET = Collections.unmodifiableSet( new HashSet() );

    private static final Collection PROTECTED_ITEMS = new ArrayList();
    private static final Attributes ENTRY = new LockableAttributesImpl();
    private static final Attributes FULL_ENTRY = new LockableAttributesImpl();

    static
    {
        Collection mvcItems = new ArrayList();
        mvcItems.add( new MaxValueCountItem( "testAttr", 2 ) );
        PROTECTED_ITEMS.add( new ProtectedItem.MaxValueCount( mvcItems ) );

        ENTRY.put( "testAttr", "1" );

        Attribute attr = new LockableAttributeImpl( "testAttr" );
        attr.add( "1" );
        attr.add( "2" );
        attr.add( "3" );
        FULL_ENTRY.put( attr );
    }


    public void testWrongScope() throws Exception
    {
        MaxValueCountFilter filter = new MaxValueCountFilter();
        Collection tuples = new ArrayList();
        tuples.add( new ACITuple( EMPTY_COLLECTION, AuthenticationLevel.NONE, EMPTY_COLLECTION, EMPTY_SET, true, 0 ) );

        tuples = Collections.unmodifiableCollection( tuples );

        Assert.assertEquals( tuples, filter.filter( tuples, OperationScope.ATTRIBUTE_TYPE, null, null, null, null,
            null, null, null, null, null, null, null ) );

        Assert.assertEquals( tuples, filter.filter( tuples, OperationScope.ENTRY, null, null, null, null, null, null,
            null, null, null, null, null ) );
    }


    public void testZeroTuple() throws Exception
    {
        MaxValueCountFilter filter = new MaxValueCountFilter();

        Assert.assertEquals( 0, filter.filter( EMPTY_COLLECTION, OperationScope.ATTRIBUTE_TYPE_AND_VALUE, null, null,
            null, null, null, null, null, null, null, null, null ).size() );
    }


    public void testDenialTuple() throws Exception
    {
        MaxValueCountFilter filter = new MaxValueCountFilter();
        Collection tuples = new ArrayList();
        tuples.add( new ACITuple( EMPTY_COLLECTION, AuthenticationLevel.NONE, PROTECTED_ITEMS, EMPTY_SET, false, 0 ) );

        tuples = Collections.unmodifiableCollection( tuples );

        Assert.assertEquals( tuples, filter.filter( tuples, OperationScope.ATTRIBUTE_TYPE_AND_VALUE, null, null, null,
            null, null, null, "testAttr", null, ENTRY, null, null ) );
        Assert.assertEquals( tuples, filter.filter( tuples, OperationScope.ATTRIBUTE_TYPE_AND_VALUE, null, null, null,
            null, null, null, "testAttr", null, FULL_ENTRY, null, null ) );
    }


    public void testGrantTuple() throws Exception
    {
        MaxValueCountFilter filter = new MaxValueCountFilter();
        Collection tuples = new ArrayList();
        tuples.add( new ACITuple( EMPTY_COLLECTION, AuthenticationLevel.NONE, PROTECTED_ITEMS, EMPTY_SET, true, 0 ) );

        Assert.assertEquals( 1, filter.filter( tuples, OperationScope.ATTRIBUTE_TYPE_AND_VALUE, null, null, null, null,
            null, null, "testAttr", null, ENTRY, null, ENTRY ).size() );

        Assert.assertEquals( 0, filter.filter( tuples, OperationScope.ATTRIBUTE_TYPE_AND_VALUE, null, null, null, null,
            null, null, "testAttr", null, FULL_ENTRY, null, FULL_ENTRY ).size() );
    }
}
