#!/bin/sh

OUTPUTDIR='target/site/docs/api'

SOURCEPATH=$(find . -maxdepth 4 -name src | awk '{ print $1"/main/java" }' | tr '\n' ':')

PACKAGES='org.apache.directory.server'

#EXCLUDES="org.apache.mina.examples:$(grep -h '^package org\.apache\.mina.*support;$' * -R | sed 's/^package \(.*\.support\);/\1/g' | sed 's/\r//g' | tr '\n' ':' | sed 's/:$//g'| sort -u)"

javadoc -d $OUTPUTDIR -sourcepath $SOURCEPATH -subpackages $PACKAGES #-exclude $EXCLUDES 
