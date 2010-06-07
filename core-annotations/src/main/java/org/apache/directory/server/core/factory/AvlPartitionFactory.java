/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.server.core.factory;


import java.io.File;
import java.util.Set;

import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.avl.AvlPartition;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.server.xdbm.impl.avl.AvlIndex;
import org.apache.directory.shared.ldap.entry.Entry;
import org.apache.directory.shared.ldap.name.DN;


/**
 * A factory used to generate {@link AvlPartition}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AvlPartitionFactory implements PartitionFactory
{

    /**
     * {@inheritDoc}
     */
    public AvlPartition createPartition( String id, String suffix, int cacheSize, File workingDirectory )
        throws Exception
    {
        AvlPartition partition = new AvlPartition();
        partition.setId( id );
        partition.setSuffix( new DN( suffix ) );
        partition.setCacheSize( 500 );
        partition.setPartitionDir( workingDirectory );
        return partition;
    }


    /**
     * {@inheritDoc}
     */
    public void addIndex( Partition partition, String attributeId, int cacheSize ) throws Exception
    {
        if ( !( partition instanceof AvlPartition ) )
        {
            throw new IllegalArgumentException( "Partition must be a AvlPartition" );
        }

        AvlPartition avlPartition = ( AvlPartition ) partition;
        Set<Index<? extends Object, Entry, Long>> indexedAttributes = avlPartition.getIndexedAttributes();

        AvlIndex<Object, Entry> index = new AvlIndex<Object, Entry>( attributeId );
        //index.setCacheSize( cacheSize );

        indexedAttributes.add( index );
        avlPartition.setIndexedAttributes( indexedAttributes );
    }

}
