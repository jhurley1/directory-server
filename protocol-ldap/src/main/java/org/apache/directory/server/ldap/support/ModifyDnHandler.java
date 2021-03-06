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
package org.apache.directory.server.ldap.support;

 
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ReferralException;
import javax.naming.ldap.LdapContext;

import org.apache.directory.server.core.configuration.StartupConfiguration;
import org.apache.directory.server.ldap.SessionRegistry;
import org.apache.directory.shared.ldap.exception.LdapException;
import org.apache.directory.shared.ldap.message.Control;
import org.apache.directory.shared.ldap.message.LdapResult;
import org.apache.directory.shared.ldap.message.ManageDsaITControl;
import org.apache.directory.shared.ldap.message.ModifyDnRequest;
import org.apache.directory.shared.ldap.message.ReferralImpl;
import org.apache.directory.shared.ldap.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.util.ExceptionUtils;

import org.apache.mina.common.IoSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A single reply handler for {@link org.apache.directory.shared.ldap.message.ModifyDnRequest}s.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class ModifyDnHandler implements LdapMessageHandler
{
    private static final Logger log = LoggerFactory.getLogger( ModifyDnHandler.class );
    private static Control[] EMPTY_CONTROLS = new Control[0];

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public void messageReceived( IoSession session, Object request )
    {
        ModifyDnRequest req = ( ModifyDnRequest ) request;
        LdapResult result = req.getResultResponse().getLdapResult();

        if ( IS_DEBUG )
        {
            log.debug( "req.getName() == [" + req.getName() + "]" );
        }

        if ( req.getName().isEmpty() )
        {
            // it is not allowed to modify the name of the Root DSE
            String msg = "Modify DN is not allowed on Root DSE.";
            result.setResultCode( ResultCodeEnum.PROTOCOLERROR );
            result.setErrorMessage( msg );
            session.write( req.getResultResponse() );
        }
        else
        {
            try
            {
                LdapContext ctx = SessionRegistry.getSingleton().getLdapContext( session, null, true );
                
                if ( req.getControls().containsKey( ManageDsaITControl.CONTROL_OID ) )
                {
                    ctx.addToEnvironment( Context.REFERRAL, "ignore" );
                }
                else
                {
                    ctx.addToEnvironment( Context.REFERRAL, "throw" );
                }
                
                ctx.setRequestControls( ( Control[] ) req.getControls().values().toArray( EMPTY_CONTROLS ) );
                String deleteRDN = String.valueOf( req.getDeleteOldRdn() );
                ctx.addToEnvironment( "java.naming.ldap.deleteRDN", deleteRDN );

                if ( req.isMove() )
                {
                    LdapDN oldDn = req.getName();
                    LdapDN newDn = null;

                    LdapDN newSuperior = req.getNewSuperior();
                    
                    if ( newSuperior.isEmpty() )
                    {
                        if ( oldDn.isEmpty() )
                        {
                            newDn = oldDn;
                        }
                        else
                        {
                            newDn = (LdapDN)oldDn.getPrefix( oldDn.size() - 1 );
                        }
                    }
                    else
                    {
                        newDn = newSuperior;
                    }

                    if ( req.getNewRdn() != null )
                    {
                        newDn.add( req.getNewRdn() );
                    }
                    else
                    {
                        newDn.add( oldDn.getRdn() );
                    }

                    ctx.rename( req.getName(), newDn );
                }
                else
                {
                    LdapDN newDn = ( LdapDN ) req.getName().clone();
                    newDn.remove( newDn.size() - 1 );
                    newDn.add( req.getNewRdn() );
                    ctx.rename( req.getName(), newDn );
                }
            }
            catch ( ReferralException e )
            {
                ReferralImpl refs = new ReferralImpl();
                result.setReferral( refs );
                result.setResultCode( ResultCodeEnum.REFERRAL );
                result.setErrorMessage( "Encountered referral attempting to handle modifyDn request." );
                result.setMatchedDn( (LdapDN)e.getResolvedName() );

                do
                {
                    refs.addLdapUrl( ( String ) e.getReferralInfo() );
                }
                while ( e.skipReferral() );
                
                session.write( req.getResultResponse() );
                return;
            }
            catch ( NamingException e )
            {
                String msg = "failed to modify DN of entry " + req.getName() + ": " + e.getMessage();
                
                if ( IS_DEBUG )
                {
                    msg += ":\n" + ExceptionUtils.getStackTrace( e );
                }

                ResultCodeEnum code;
                
                if ( e instanceof LdapException )
                {
                    code = ( ( LdapException ) e ).getResultCode();
                }
                else
                {
                    code = ResultCodeEnum.getBestEstimate( e, req.getType() );
                }

                result.setResultCode( code );
                result.setErrorMessage( msg );
                
                if ( ( e.getResolvedName() != null )
                    && ( ( code == ResultCodeEnum.NOSUCHOBJECT ) || ( code == ResultCodeEnum.ALIASPROBLEM )
                        || ( code == ResultCodeEnum.INVALIDDNSYNTAX ) || ( code == ResultCodeEnum.ALIASDEREFERENCINGPROBLEM ) ) )
                {
                    result.setMatchedDn( (LdapDN)e.getResolvedName() );
                }

                session.write( req.getResultResponse() );
                return;
            }

            result.setResultCode( ResultCodeEnum.SUCCESS );
            session.write( req.getResultResponse() );
        }
    }


    public void init( StartupConfiguration cfg )
    {
    }
}
