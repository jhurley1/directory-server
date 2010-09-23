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
package org.apache.directory.daemon.installers.nsis;


import java.io.File;

import org.apache.directory.daemon.installers.Target;


/**
 * A Nullsoft Installer System (NSIS) installer for the Windows platform.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NsisTarget extends Target
{
    private File nsisCompiler = new File( "/usr/bin/makensis" );


    /**
     * Creates a new instance of NsisTarget.
     */
    public NsisTarget()
    {
        setOsName( Target.OS_NAME_WINDOWS );
        setOsArch( Target.OS_ARCH_X86 );
    }


    /**
     * Sets the NSIS compiler utility.
     *
     * @param nsisCompiler
     *      the NSIS compiler utility
     */
    public void setNsisCompiler( File nsisCompiler )
    {
        this.nsisCompiler = nsisCompiler;
    }


    /**
     * Gets the NSIS compiler utility.
     *
     * @return
     *      the NSIS compiler utility
     */
    public File getNsisCompiler()
    {
        return nsisCompiler;
    }
}
