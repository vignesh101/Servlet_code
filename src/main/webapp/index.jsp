<?xml version="1.0" encoding="UTF-8"?>
<settings
	xmlns="http://maven.apache.org/SETTINGS/1.0.0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">

	<!-- Fiserv Archetype Guidelines - settings.xml -->

		<!-- Fiserv DevSecOps Team - 2023-03-11 -->

		<!-- Welcome, these guidelines explains the good practices and requirements to generate and publish a package -->
		<!-- All steps you will see, help us to ensure the standards and security for all of us -->
		<!-- But, if you find some improvement point, your suggestion will be appreciated by the DevSecOps Team :-) -->

		<!-- Tip: use the search tool of your editor to guide yourself under each step following the sequence (1.1, 1.2, 1.3...) -->

		<!-- Use this file within pom.xml, you can find more information there -->

		<!-- STEP 3 - ARTIFACT REPOSITORY PUBLISH -->
		<!-- Requirements: You should complete the STEP 2 -->

	<pluginGroups></pluginGroups>
	<!--SERVERS-->
	<profiles>
		<profile>
			<id>default-profile</id>
			<repositories>
				<repository>
					<id>nexus-fiserv-libs-apm0004547</id>
					<name>Nexus fiserv libs</name>
					<url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/</url>
					<releases>
					<enabled>true</enabled>
					</releases>
					<snapshots>
					<enabled>false</enabled>
					</snapshots>
			   </repository>
			   <repository>
					<id>maven-apm0004547-lib</id>
					<name>maven fiserv libs</name>
					<url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/</url>
					<releases>
					<enabled>true</enabled>
					</releases>
					<snapshots>
					<enabled>false</enabled>
					</snapshots>
			   </repository>
			   <repository>
					<id>maven-apm0004547-snapshots</id>
					<name>maven snapshots libs</name>
					<url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/</url>
					<releases>
					<enabled>true</enabled>
					</releases>
					<snapshots>
					<enabled>false</enabled>
					</snapshots>
			   </repository>
			   <repository>
					<id>maven-apm0004547-releases</id>
					<name>maven releases libs</name>
					<url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-releases/</url>
					<releases>
					<enabled>true</enabled>
					</releases>
					<snapshots>
					<enabled>false</enabled>
					</snapshots>
			   </repository>
			</repositories>
		</profile>
	</profiles>
	<!-- Step 3.7 - Go to the settings.xml file, you have the two <server> credentials configurated -->
	<servers>
		<server>
			<id>releases</id>
			<!-- ATENTION: If the value above is a variable, ensure that is set before run -->
			<username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
		</server>
		<server>
			<id>snapshots</id>
			<!-- ATENTION: If the value above is a variable, ensure that is set before run -->
			<username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
		</server>
		<server>
            <id>nexus-fiserv-libs-apm0004547</id>
            <username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
        </server>
		<server>
            <id>maven-apm0004547-releases</id>
            <username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
        </server>
		<server>
            <id>maven-apm0004547-snapshots</id>
            <username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
        </server>
		<server>
            <id>maven-apm0004547-lib</id>
            <username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
        </server>
		<server>
            <id>nexus-fiserv-protector</id>
            <username>F1J503X</username>
	    <password>Alohomora7!</password>
        </server>
		<server>
            <id>Maven_Central</id>
            <username>F1J503X</username>
	    <password>Alohomora7!</password>
        </server>
	</servers>
	<!--MIRRORS-->
	<mirrors>
		<!-- Step 3.8 - Make sure a <mirror> is set for package restore -->
		<!-- NOTE: No configuration is needed setup the package restore in pom.xml -->
		<mirror>
			<id>Maven_Central</id>
			<mirrorOf>central</mirrorOf>
			 <!-- ATENTION: If the value above is a variable, ensure that is set before run -->
			<url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/</url>
		</mirror> 
	</mirrors>

	<!--PROFILES-->
	
	<activeProfiles>
		<activeProfile>default-profile</activeProfile>
	</activeProfiles>
	<!-- RUN A TEST -->
		<!-- Make sure you have generated the artifacts as described at the STEP 2 - RUN TESTS -->
		<!-- If you have generated an artifact in 'target/' folder, make sure validate if it is a release or snapshot -->
		<!-- Check the STEP 2 - RUN TESTS, to validate it -->
		
		<!-- For snapshots, simply run: 'mvn deploy -Puat -s settings.xml' (or other profile that contains the tag <snapshot>)-->
		<!-- For releaes, simply run: 'mvn deploy -Pprd -settings.xml' (or other profile that NOT contains the tag <snapshot>) -->

		<!-- See the logs and get in your repository to validate if the package is successfull uploaded -->
		<!-- You will probably see the same version contained in 'target/maven-archiver/pom.properties' -->
		<!-- For snapshots, it will append a timestamp string at the version, but don't worry, it's alright -->

	<!-- Fiserv Archetype Guidelines - settings.xml -->

</settings>
HOT/maven-metadata.xml from/to Maven_Central (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/): status code: 403, reason phrase: Forbidden (403)
Downloading from Maven_Central: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
Downloading from snapshots: https://nexus.paulista.local/repository/maven-snapshots/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
Downloading from nexus-fiserv-protector: https://nexus-ci.onefiserv.net/repository/fiservprotector-maven/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
Downloading from nexus-voltage-maven: https://nexus-ci.onefiserv.net/repository/voltage-maven/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
Downloading from releases: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-releases/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
[WARNING] br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of Maven_Central has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml from/to Maven_Central (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/): status code: 403, reason phrase: Forbidden (403)
[WARNING] br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of Maven_Central has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml from/to Maven_Central (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/): status code: 403, reason phrase: Forbidden (403)
[WARNING] br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of Maven_Central has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml from/to Maven_Central (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/): status code: 403, reason phrase: Forbidden (403)
[INFO] ------------------------------------------------------------------------
[INFO] Reactor Summary:
[INFO]
[INFO] e-sitef-ejb 5.150-SNAPSHOT ......................... FAILURE [ 17.633 s]
[INFO] e-sitef-relatorio-ejb 5.150-SNAPSHOT ............... SKIPPED
[INFO] e-sitef-admin-ear 5.150-SNAPSHOT ................... SKIPPED
[INFO] e-sitef-pagamento 5.150-SNAPSHOT ................... SKIPPED
[INFO] e-sitef-loja 5.150-SNAPSHOT ........................ SKIPPED
[INFO] e-sitef-admin 5.150-SNAPSHOT ....................... SKIPPED
[INFO] e-sitef-parent-jboss 1.1.0 ......................... SKIPPED
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  26.754 s
[INFO] Finished at: 2025-04-03T15:05:15+05:30
[INFO] ------------------------------------------------------------------------
[ERROR] Failed to execute goal on project e-sitef-ejb: Could not resolve dependencies for project br.com.softwareexpress.esitef:e-sitef-ejb:ejb:5.150-SNAPSHOT: Failed to collect dependencies at br.com.softwareexpress.sitef:LibSiTef:jar:1.010: Failed to read artifact descriptor for br.com.softwareexpress.sitef:LibSiTef:jar:1.010: The following artifacts could not be resolved: br.com.softwareexpress.sitef:LibSiTef:pom:1.010 (present, but unavailable): Could not transfer artifact br.com.softwareexpress.sitef:LibSiTef:pom:1.010 from/to Maven_Central (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-snapshots/): status code: 403, reason phrase: Forbidden (403) -> [Help 1]
[ERROR]
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR]
[ERROR] For more information about the errors and possible solutions, please read the following art
