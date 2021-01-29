#!/bin/bash
     
#for cert in `ls /tmp/*pem`; do
#  keytool -cacerts -storepass changeit -importcert -noprompt -alias `basename $cert` -file $cert
#done

sed -i "s/https:\/\/localhost:8443/${CAS_SERVER_NAME//\//\\/}/g" /opt/cas/conf/saml/idp-metadata.xml

JAVA_OPTS=-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djava.security.egd=file:/dev/./urandom \
 -XX:+TieredCompilation -XX:TieredStopAtLevel=1 -Dcas.standalone.configurationDirectory=/opt/cas/conf

catalina.sh run