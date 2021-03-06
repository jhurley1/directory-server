##############  W O R K  I N  P R O G R E S S  ############## 

To generate the site for ApacheDS Project change to the
master project's root directory and execute

	mvn site --non-recursive

The site will be generated at

	target/site

For deploying the site to the remote server you need to
configure the Apache Web Server access parameters
in your local m2 configuration file which is normally at

	$HOME/.m2/settings.xml

A typical settings file which contains only this
configuration would generally look as follows (for UNIX):

	<settings>
	  <servers>
	    <server>
	      <id>apache.websites</id>
	      <username>YourApacheUserName</username>
	      <privateKey>$HOME/.ssh/id_rsa</privateKey>
	      <directoryPermissions>775</directoryPermissions>
	      <filePermissions>664</filePermissions>
	    </server>
	  </servers>
	</settings>

To deploy the site to remote server execute

	mvn site-deploy --non-recursive
