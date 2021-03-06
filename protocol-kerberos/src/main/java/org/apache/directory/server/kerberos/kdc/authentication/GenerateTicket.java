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
package org.apache.directory.server.kerberos.kdc.authentication;


import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.directory.server.kerberos.kdc.KdcConfiguration;
import org.apache.directory.server.kerberos.shared.exceptions.ErrorType;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.messages.KdcRequest;
import org.apache.directory.server.kerberos.shared.messages.components.EncTicketPart;
import org.apache.directory.server.kerberos.shared.messages.components.EncTicketPartModifier;
import org.apache.directory.server.kerberos.shared.messages.components.Ticket;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptedData;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.messages.value.KdcOptions;
import org.apache.directory.server.kerberos.shared.messages.value.KerberosTime;
import org.apache.directory.server.kerberos.shared.messages.value.TicketFlags;
import org.apache.directory.server.kerberos.shared.messages.value.TransitedEncoding;
import org.apache.directory.server.kerberos.shared.service.LockBox;
import org.apache.mina.common.IoSession;
import org.apache.mina.handler.chain.IoHandlerCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class GenerateTicket implements IoHandlerCommand
{
    /** the log for this class */
    private static final Logger log = LoggerFactory.getLogger( GenerateTicket.class );

    private String contextKey = "context";

    public void execute( NextCommand next, IoSession session, Object message ) throws Exception
    {
        AuthenticationContext authContext = ( AuthenticationContext ) session.getAttribute( getContextKey() );

        KdcRequest request = authContext.getRequest();
        LockBox lockBox = authContext.getLockBox();
        KerberosPrincipal serverPrincipal = request.getServerPrincipal();
        EncryptionKey serverKey = authContext.getServerEntry().getEncryptionKey();
        KerberosPrincipal ticketPrincipal = request.getServerPrincipal();
        EncTicketPartModifier newTicketBody = new EncTicketPartModifier();
        KdcConfiguration config = authContext.getConfig();
        EncryptionKey sessionKey = authContext.getSessionKey();

        if ( request.getKdcOptions().get( KdcOptions.FORWARDABLE ) )
        {
            newTicketBody.setFlag( TicketFlags.FORWARDABLE );
        }

        if ( request.getKdcOptions().get( KdcOptions.PROXIABLE ) )
        {
            newTicketBody.setFlag( TicketFlags.PROXIABLE );
        }

        if ( request.getKdcOptions().get( KdcOptions.ALLOW_POSTDATE ) )
        {
            newTicketBody.setFlag( TicketFlags.MAY_POSTDATE );
        }

        if ( request.getKdcOptions().get( KdcOptions.RENEW ) || request.getKdcOptions().get( KdcOptions.VALIDATE )
            || request.getKdcOptions().get( KdcOptions.PROXY ) || request.getKdcOptions().get( KdcOptions.FORWARDED )
            || request.getKdcOptions().get( KdcOptions.ENC_TKT_IN_SKEY ) )
        {
            throw new KerberosException( ErrorType.KDC_ERR_BADOPTION );
        }

        newTicketBody.setSessionKey( sessionKey );
        newTicketBody.setClientPrincipal( request.getClientPrincipal() );
        newTicketBody.setTransitedEncoding( new TransitedEncoding() );

        KerberosTime now = new KerberosTime();
        newTicketBody.setAuthTime( now );

        if ( request.getKdcOptions().get( KdcOptions.POSTDATED ) )
        {
            // TODO - possibly allow req.from range
            if ( !config.isPostdateAllowed() )
            {
                throw new KerberosException( ErrorType.KDC_ERR_POLICY );
            }
            
            newTicketBody.setFlag( TicketFlags.INVALID );
            newTicketBody.setStartTime( request.getFrom() );
        }

        long till = 0;
        
        if ( request.getTill().getTime() == 0 )
        {
            till = Long.MAX_VALUE;
        }
        else
        {
            till = request.getTill().getTime();
        }
        
        long endTime = Math.min( now.getTime() + config.getMaximumTicketLifetime(), till );
        KerberosTime kerberosEndTime = new KerberosTime( endTime );
        newTicketBody.setEndTime( kerberosEndTime );

        long tempRtime = 0;
        if ( request.getKdcOptions().get( KdcOptions.RENEWABLE_OK ) && request.getTill().greaterThan( kerberosEndTime ) )
        {
            request.getKdcOptions().set( KdcOptions.RENEWABLE );
            tempRtime = request.getTill().getTime();
        }

        if ( tempRtime == 0 )
        {
            tempRtime = Long.MAX_VALUE;
        }
        else
        {
            tempRtime = request.getRtime().getTime();
        }

        if ( request.getKdcOptions().get( KdcOptions.RENEWABLE ) )
        {
            newTicketBody.setFlag( TicketFlags.RENEWABLE );

            /*
             * 'from' KerberosTime is OPTIONAL
             */
            KerberosTime fromTime = request.getFrom();

            if ( fromTime == null )
            {
                fromTime = new KerberosTime();
            }

            long renewTill = Math.min( fromTime.getTime() + config.getMaximumRenewableLifetime(), tempRtime );
            newTicketBody.setRenewTill( new KerberosTime( renewTill ) );
        }

        if ( request.getAddresses() != null )
        {
            newTicketBody.setClientAddresses( request.getAddresses() );
        }

        EncTicketPart ticketPart = newTicketBody.getEncTicketPart();

        EncryptedData encryptedData = lockBox.seal( serverKey, ticketPart );

        Ticket newTicket = new Ticket( ticketPrincipal, encryptedData );
        newTicket.setEncTicketPart( ticketPart );

        if ( log.isDebugEnabled() )
        {
            log.debug( "Ticket will be issued for access to " + serverPrincipal.toString() + "." );
        }

        authContext.setTicket( newTicket );

        next.execute( session, message );
    }

    public String getContextKey()
    {
        return ( this.contextKey );
    }
}
