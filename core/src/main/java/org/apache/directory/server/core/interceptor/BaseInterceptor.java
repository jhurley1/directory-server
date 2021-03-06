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
package org.apache.directory.server.core.interceptor;


import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;

import org.apache.directory.server.core.DirectoryServiceConfiguration;
import org.apache.directory.server.core.authn.LdapPrincipal;
import org.apache.directory.server.core.configuration.PartitionConfiguration;
import org.apache.directory.server.core.configuration.InterceptorConfiguration;
import org.apache.directory.server.core.invocation.InvocationStack;
import org.apache.directory.server.core.jndi.ServerContext;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.message.ModificationItemImpl;
import org.apache.directory.shared.ldap.name.LdapDN;


/**
 * A easy-to-use implementation of {@link Interceptor}.  All methods are
 * implemented to pass the flow of control to next interceptor by defaults.
 * Please override the methods you have concern in.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public abstract class BaseInterceptor implements Interceptor
{
    /**
     * Returns {@link LdapPrincipal} of current context.
     */
    public static LdapPrincipal getPrincipal()
    {
        ServerContext ctx = ( ServerContext ) getContext();
        return ctx.getPrincipal();
    }


    /**
     * Returns the current JNDI {@link Context}.
     */
    public static LdapContext getContext()
    {
        return ( LdapContext ) InvocationStack.getInstance().peek().getCaller();
    }


    /**
     * Creates a new instance.
     */
    protected BaseInterceptor()
    {
    }


    /**
     * This method does nothing by default.
     */
    public void init( DirectoryServiceConfiguration factoryCfg, InterceptorConfiguration cfg ) throws NamingException
    {
    }


    /**
     * This method does nothing by default.
     */
    public void destroy()
    {
    }


    // ------------------------------------------------------------------------
    // Interceptor's Invoke Method
    // ------------------------------------------------------------------------

    public void add(NextInterceptor next, LdapDN normName, Attributes entry) throws NamingException
    {
        next.add(normName, entry );
    }


    public void delete( NextInterceptor next, LdapDN name ) throws NamingException
    {
        next.delete( name );
    }


    public LdapDN getMatchedName ( NextInterceptor next, LdapDN dn ) throws NamingException
    {
        return next.getMatchedName( dn );
    }


    public Attributes getRootDSE( NextInterceptor next ) throws NamingException
    {
        return next.getRootDSE();
    }


    public LdapDN getSuffix ( NextInterceptor next, LdapDN dn ) throws NamingException
    {
        return next.getSuffix( dn );
    }


    public boolean hasEntry( NextInterceptor next, LdapDN name ) throws NamingException
    {
        return next.hasEntry( name );
    }


    public boolean isSuffix( NextInterceptor next, LdapDN name ) throws NamingException
    {
        return next.isSuffix( name );
    }


    public NamingEnumeration list( NextInterceptor next, LdapDN base ) throws NamingException
    {
        return next.list( base );
    }


    public Iterator listSuffixes ( NextInterceptor next ) throws NamingException
    {
        return next.listSuffixes();
    }


    public Attributes lookup( NextInterceptor next, LdapDN dn, String[] attrIds ) throws NamingException
    {
        return next.lookup( dn, attrIds );
    }


    public Attributes lookup( NextInterceptor next, LdapDN name ) throws NamingException
    {
        return next.lookup( name );
    }


    public void modify( NextInterceptor next, LdapDN name, int modOp, Attributes mods ) throws NamingException
    {
        next.modify( name, modOp, mods );
    }


    public void modify( NextInterceptor next, LdapDN name, ModificationItemImpl[] mods ) throws NamingException
    {
        next.modify( name, mods );
    }


    public void modifyRn( NextInterceptor next, LdapDN name, String newRn, boolean deleteOldRn ) throws NamingException
    {
        next.modifyRn( name, newRn, deleteOldRn );
    }


    public void move( NextInterceptor next, LdapDN oriChildName, LdapDN newParentName, String newRn, boolean deleteOldRn )
        throws NamingException
    {
        next.move( oriChildName, newParentName, newRn, deleteOldRn );
    }


    public void move( NextInterceptor next, LdapDN oriChildName, LdapDN newParentName ) throws NamingException
    {
        next.move( oriChildName, newParentName );
    }


    public NamingEnumeration search( NextInterceptor next, LdapDN base, Map env, ExprNode filter,
                                     SearchControls searchCtls ) throws NamingException
    {
        return next.search( base, env, filter, searchCtls );
    }


    public void addContextPartition( NextInterceptor next, PartitionConfiguration cfg ) throws NamingException
    {
        next.addContextPartition( cfg );
    }


    public void removeContextPartition( NextInterceptor next, LdapDN suffix ) throws NamingException
    {
        next.removeContextPartition( suffix );
    }


    public boolean compare( NextInterceptor next, LdapDN name, String oid, Object value ) throws NamingException
    {
        return next.compare( name, oid, value );
    }


    public void bind( NextInterceptor next, LdapDN bindDn, byte[] credentials, List mechanisms, String saslAuthId )
        throws NamingException
    {
        next.bind( bindDn, credentials, mechanisms, saslAuthId );
    }


    public void unbind( NextInterceptor next, LdapDN bindDn ) throws NamingException
    {
        next.unbind( bindDn );
    }
}
