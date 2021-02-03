#!/bin/bash
     
for cert in `ls /tmp/*pem`; do
  keytool -storepass password -keystore /opt/cas/tomcat.jks -import -alias `basename $cert` -file $cert -trustcacerts -noprompt
  keytool -cacerts -storepass changeit -importcert -noprompt -alias `basename $cert` -file $cert
done

sed -i "s/https:\/\/localhost:9443/${CAS_SERVER_NAME//\//\\/}/g" /opt/cas/conf/saml/idp-metadata.xml

JAVA_OPTS=-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djava.security.egd=file:/dev/./urandom \
 -XX:+TieredCompilation -XX:TieredStopAtLevel=1 -Dcas.standalone.configurationDirectory=/opt/cas/conf

catalina.sh run
