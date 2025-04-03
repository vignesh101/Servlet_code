<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
    <!-- Fiserv Archetype Guidelines - settings.xml -->
    <!-- Fiserv DevSecOps Team - 2023-03-11 -->
    <!-- Welcome, these guidelines explain the good practices and requirements to generate and publish a package -->
    <!-- All steps you will see help us to ensure the standards and security for all of us -->
    <!-- But, if you find some improvement point, your suggestion will be appreciated by the DevSecOps Team :-) -->
    <!-- Tip: use the search tool of your editor to guide yourself under each step following the sequence (1.1, 1.2, 1.3...) -->
    <!-- Use this file within pom.xml, you can find more information there -->
    <!-- STEP 3 - ARTIFACT REPOSITORY PUBLISH -->
    <!-- Requirements: You should complete STEP 2 -->

    <pluginGroups/>
    
    <!-- SERVERS -->
    <!-- Step 3.7 - Go to the settings.xml file, you have the two <server> credentials configured -->
    <servers>
        <server>
            <id>releases</id>
            <!-- ATENTION: If the value above is a variable, ensure that is set before run -->
            <username>7hawnKR-</username>
            <password>6BXJ1nGzDqnBCG1gBmbqu5gB0cvSUffVBOrjJsoskjZd</password>
        </server>
        <server>
            <id>snapshots</id>
            <!-- ATENTION: If the value above is a variable, ensure that is set before run -->
            <username>7hawnKR-</username>
            <password>6BXJ1nGzDqnBCG1gBmbqu5gB0cvSUffVBOrjJsoskjZd</password>
        </server>
        <server>
            <id>nexus-apm0004547-lib</id>
            <username>P_KDOyOd</username>
            <password>OiNR9dQtVqWgCkFG0dEyOsOeGMHPWHGJOTyfyyO46W1U</password>
        </server>
        <server>
            <id>nexus-fiserv-protector</id>
            <username>7hawnKR-</username>
            <password>6BXJ1nGzDqnBCG1gBmbqu5gB0cvSUffVBOrjJsoskjZd</password>
        </server>
        <server>
            <id>Maven_Central</id>
            <username>7hawnKR-</username>
            <password>6BXJ1nGzDqnBCG1gBmbqu5gB0cvSUffVBOrjJsoskjZd</password>
        </server>
        <server>
            <id>Nexus</id>
            <username>7hawnKR-</username>
            <password>6BXJ1nGzDqnBCG1gBmbqu5gB0cvSUffVBOrjJsoskjZd</password>
        </server>
        <server>
            <id>nexus_paulista</id>
            <username>provider-maven</username>
            <password>provider123</password>
            <configuration>
                <ssl>
                    <trustAll>true</trustAll>
                </ssl>
            </configuration>
        </server>
        <server>
            <id>nexus.paulista.local</id>
            <configuration>
                <ssl>
                    <trustAll>true</trustAll>
                </ssl>
            </configuration>
        </server>
        <server>
            <id>nexus_paulista_snapshots</id>
            <username>provider-maven</username>
            <password>provider123</password>
            <configuration>
                <ssl>
                    <trustAll>true</trustAll>
                </ssl>
            </configuration>
        </server>
        <server>
            <id>fiserv_central</id>
            <username>f******</username>
            <password></password>
        </server>
    </servers>

    <!-- MIRRORS -->
    <mirrors>
        <!-- Step 3.8 - Make sure a <mirror> is set for package restore -->
        <!-- NOTE: No configuration is needed setup the package restore in pom.xml -->
        <mirror>
            <id>Maven_Central</id>
            <mirrorOf>central</mirrorOf>
            <!-- ATENTION: If the value above is a variable, ensure that is set before run -->
            <url>https://nexus-dev.onefiserv.net/repository/Maven_Central/</url>
        </mirror>
        <mirror>
            <id>Nexus</id>
            <mirrorOf>central</mirrorOf>
            <name>Nexus Proxy central</name>
            <url>https://nexus-dev.onefiserv.net/repository/Maven_Central/</url>
        </mirror>
    </mirrors>

    <!-- PROFILES -->
    <profiles>
        <profile>
            <id>dev</id>
            <properties>
                <spring.profiles.active>dev</spring.profiles.active>
                <activeProfile>dev</activeProfile>
                <snapshot>-SNAPSHOT</snapshot>
            </properties>
        </profile>
        <profile>
            <id>uat</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <properties>
                <spring.profiles.active>uat</spring.profiles.active>
                <activeProfile>uat</activeProfile>
                <snapshot>-SNAPSHOT</snapshot>
            </properties>
        </profile>
        <profile>
            <id>prd</id>
            <properties>
                <spring.profiles.active>prd</spring.profiles.active>
                <activeProfile>prd</activeProfile>
                <snapshot/>
            </properties>
        </profile>
        <profile>
            <id>nexus.paulista.local</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <repositories>
                <repository>
                    <id>nexus_paulista</id>
                    <name>Nexus Central</name>
                    <url>https://nexus.paulista.local/repository/maven-group/</url>
                    <releases>
                        <enabled>true</enabled>
                    </releases>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                </repository>
                <repository>
                    <id>nexus-apm0004547-lib</id>
                    <name>Nexus APM</name>
                    <url>https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/</url>
                    <releases>
                        <enabled>true</enabled>
                    </releases>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                </repository>
                <repository>
                    <id>nexus_paulista_snapshots</id>
                    <name>Nexus Snapshots</name>
                    <url>https://nexus.paulista.local/repository/maven-snapshots/</url>
                    <releases>
                        <enabled>false</enabled>
                    </releases>
                </repository>
                <repository>
                    <id>fiserv_central</id>
                    <name>Nexus Central</name>
                    <url>https://nexus-dev.onefiserv.net/repository/Maven_Central</url>
                    <releases>
                        <enabled>true</enabled>
                    </releases>
                </repository>
            </repositories>
            <pluginRepositories>
                <pluginRepository>
                    <id>nexus_paulista</id>
                    <name>Nexus Central</name>
                    <url>https://nexus.paulista.local/repository/maven-group/</url>
                    <releases>
                        <enabled>true</enabled>
                    </releases>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                </pluginRepository>
                <pluginRepository>
                    <id>nexus_paulista_snapshots</id>
                    <name>Nexus Snapshots</name>
                    <url>https://nexus.paulista.local/repository/maven-snapshots/</url>
                    <releases>
                        <enabled>false</enabled>
                    </releases>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                </pluginRepository>
                <pluginRepository>
                    <id>fiserv_central</id>
                    <name>Nexus Central</name>
                    <url>https://nexus-dev.onefiserv.net/repository/Maven_Central</url>
                </pluginRepository>
            </pluginRepositories>
        </profile>
    </profiles>
</settings>  Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-entity/5.150-SNAPSHOT/maven-metadata.xml
[WARNING] Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-entity/5.150-SNAPSHOT/e-sitef-entity-5.150-SNAPSHOT.pom
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-service-commons/5.150-SNAPSHOT/maven-metadata.xml
[WARNING] Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-service-commons/5.150-SNAPSHOT/e-sitef-service-commons-5.150-SNAPSHOT.pom
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-client-commons/5.150-SNAPSHOT/maven-metadata.xml
[WARNING] Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-client-commons/5.150-SNAPSHOT/e-sitef-client-commons-5.150-SNAPSHOT.pom
[WARNING] The POM for com.sun.xml.bind:jaxb-impl:jar:2.2.11 is invalid, transitive dependencies (if any) will not be available, enable debug logging for more details
[WARNING] The POM for com.sun.xml.bind:jaxb-core:jar:2.2.11 is invalid, transitive dependencies (if any) will not be available, enable debug logging for more details
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/maven-metadata.xml
[WARNING] Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-hsm:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-hsm:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-hsm:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
Downloading from nexus-fiserv-libs-apm0004547: https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/br/com/softwareexpress/esitef/e-sitef-hsm/5.150-SNAPSHOT/e-sitef-hsm-5.150-SNAPSHOT.pom
[WARNING] br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-entity:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-service-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[WARNING] br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml failed to transfer from https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/ during a previous attempt. This failure was cached in the local repository and resolution will not be reattempted until the update interval of nexus-fiserv-libs-apm0004547 has elapsed or updates are forced. Original error: Could not transfer metadata br.com.softwareexpress.esitef:e-sitef-client-commons:5.150-SNAPSHOT/maven-metadata.xml from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401)
[INFO] ------------------------------------------------------------------------
[INFO] Reactor Summary:
[INFO]
[INFO] e-sitef-ejb 5.150-SNAPSHOT ......................... FAILURE [  7.483 s]
[INFO] e-sitef-relatorio-ejb 5.150-SNAPSHOT ............... SKIPPED
[INFO] e-sitef-admin-ear 5.150-SNAPSHOT ................... SKIPPED
[INFO] e-sitef-pagamento 5.150-SNAPSHOT ................... SKIPPED
[INFO] e-sitef-loja 5.150-SNAPSHOT ........................ SKIPPED
[INFO] e-sitef-admin 5.150-SNAPSHOT ....................... SKIPPED
[INFO] e-sitef-parent-jboss 1.1.0 ......................... SKIPPED
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  8.537 s
[INFO] Finished at: 2025-04-03T13:32:39+05:30
[INFO] ------------------------------------------------------------------------
[ERROR] Failed to execute goal on project e-sitef-ejb: Could not resolve dependencies for project br.com.softwareexpress.esitef:e-sitef-ejb:ejb:5.150-SNAPSHOT: Failed to collect dependencies at br.com.softwareexpress.esitef:e-sitef-entity:jar:5.150-SNAPSHOT: Failed to read artifact descriptor for br.com.softwareexpress.esitef:e-sitef-entity:jar:5.150-SNAPSHOT: The following artifacts could not be resolved: br.com.softwareexpress.esitef:e-sitef-entity:pom:5.150-SNAPSHOT (absent): Could not transfer artifact br.com.softwareexpress.esitef:e-sitef-entity:pom:5.150-SNAPSHOT from/to nexus-fiserv-libs-apm0004547 (https://nexus-ci.onefiserv.net/repository/maven-apm0004547-lib/): status code: 401, reason phrase: Unauthorized (401) -> [Help 1]
[ERROR]
