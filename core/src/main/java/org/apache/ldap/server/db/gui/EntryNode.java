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
package org.apache.ldap.server.db.gui;


import java.math.BigInteger;
import java.util.*;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.swing.tree.TreeNode;

import org.apache.ldap.common.filter.ExprNode;
import org.apache.ldap.common.name.LdapName;
import org.apache.ldap.server.db.Database;
import org.apache.ldap.server.db.IndexRecord;
import org.apache.ldap.server.db.SearchEngine;


/**
 * A node representing an entry.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class EntryNode
	implements TreeNode
{
    private final Database db;
    private final EntryNode parent;
	private final Attributes entry;
    private final ArrayList children;
    private final BigInteger id;


    public EntryNode( BigInteger id, EntryNode parent, Database db,
        Attributes entry, HashMap map )
    {
        this( id, parent, db, entry, map, null, null );
    }


    public EntryNode( BigInteger id, EntryNode parent, Database db,
        Attributes entry, HashMap map, ExprNode exprNode,
        SearchEngine engine )
    {
        this.db = db;
        this.id = id;
		this.entry = entry;
        this.children = new ArrayList();

        if ( parent == null )
        {
            this.parent = this;
        } 
        else 
        {
            this.parent = parent;
        }

		try {
            ArrayList records = new ArrayList();
            NamingEnumeration childList = db.list( id );
            while( childList.hasMore() )
            {
                IndexRecord old = ( IndexRecord ) childList.next();
                IndexRecord newRec = new IndexRecord();
                newRec.copy( old );
                records.add( newRec );
            }
            childList.close();

            Iterator list = records.iterator();
            
            while( list.hasNext() )
            {
                IndexRecord rec = ( IndexRecord ) list.next();

                if ( engine != null && exprNode != null )
                {
                    if ( db.getChildCount( rec.getEntryId() ) == 0 )
                    {
                        if( engine.evaluate( exprNode, rec.getEntryId() ) )
                        {
                            Attributes newEntry = db.lookup( rec.getEntryId() );
                            EntryNode child = new EntryNode( rec.getEntryId(),
                                    this, db, newEntry, map, exprNode, engine);
                            children.add(child);
                        }
                        else
                        {
                            continue;
                        }
                    }
                    else
                    {
                        Attributes newEntry = db.lookup( rec.getEntryId() );
                        EntryNode child = new EntryNode( rec.getEntryId(),
                            this, db, newEntry, map, exprNode, engine );
                        children.add( child );
                    }
                } 
                else
                {
                    Attributes newEntry = db.lookup( rec.getEntryId() );
                    EntryNode child = new EntryNode( rec.getEntryId(), this,
                        db, newEntry, map );
                    children.add( child );
                }
            }
        } 
        catch ( Exception e ) 
        {
            e.printStackTrace();
        }

        map.put( id, this );
    }


    public Enumeration children()
    {
        return Collections.enumeration( children );
    }


    public boolean getAllowsChildren()
    {
        return true;
    }


    public TreeNode getChildAt( int childIndex )
    {
		return ( TreeNode ) children.get( childIndex );
    }


    public int getChildCount()
    {
        return children.size();
    }


    public int getIndex( TreeNode child )
    {
        return children.indexOf( child );
    }


    public TreeNode getParent()
    {
        return parent;
    }


    public boolean isLeaf()
    {
        return children.size() <= 0;
    }


    public String getEntryDn()
        throws NamingException
    {
        return db.getEntryDn( id );
    }
    

    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        
        try
        {
            LdapName dn = new LdapName( db.getEntryDn( id ) );
            buf.append( "(" ).append( id ).append( ") " );
            buf.append( dn.getRdn() );
        }
        catch( NamingException e )
        {
            e.printStackTrace();
            buf.append( "ERROR: " + e.getMessage() );
        }
        
        if ( children.size() > 0 )
        {
            buf.append( " [" ).append( children.size() ).append( "]" );
        }
        
        return buf.toString();
    }


    public Attributes getLdapEntry()
    {
        return entry;
    }
    
    
    public BigInteger getEntryId()
    {
        return id;
    }
}
