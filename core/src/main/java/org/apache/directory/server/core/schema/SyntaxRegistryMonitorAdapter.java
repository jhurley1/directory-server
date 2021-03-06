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


import javax.naming.NamingException;

import org.apache.directory.shared.ldap.schema.Syntax;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An adapter for the SyntaxRegistry's monitor.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class SyntaxRegistryMonitorAdapter implements SyntaxRegistryMonitor
{
    private static final Logger log = LoggerFactory.getLogger( SyntaxRegistryMonitorAdapter.class );


    /* (non-Javadoc)
     * @see org.apache.directory.server.schema.SyntaxRegistryMonitor#registered(
     * org.apache.eve.schema.Syntax)
     */
    public void registered( Syntax syntax )
    {
    }


    /* (non-Javadoc)
     * @see org.apache.directory.server.schema.SyntaxRegistryMonitor#lookedUp(
     * org.apache.eve.schema.Syntax)
     */
    public void lookedUp( Syntax syntax )
    {
    }


    /* (non-Javadoc)
     * @see org.apache.directory.server.schema.SyntaxRegistryMonitor#lookupFailed(
     * java.lang.String, javax.naming.NamingException)
     */
    public void lookupFailed( String oid, NamingException fault )
    {
        if ( fault != null )
        {
            log.warn( "Failed to look up the syntax: " + oid, fault );
        }
    }


    /* (non-Javadoc)
     * @see org.apache.directory.server.schema.SyntaxRegistryMonitor#registerFailed(
     * org.apache.eve.schema.Syntax, javax.naming.NamingException)
     */
    public void registerFailed( Syntax syntax, NamingException fault )
    {
        if ( fault != null )
        {
            log.warn( "Failed to register a syntax: " + syntax, fault );
        }
    }
}
