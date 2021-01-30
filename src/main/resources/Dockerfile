FROM tomcat:9-jdk11-adoptopenjdk-hotspot

RUN sed -i '/<Connector port="8080" protocol="HTTP\/1.1"/c\<Connector port="8080" maxHttpHeaderSize="65536" protocol="HTTP/1.1"' $CATALINA_HOME/conf/server.xml
RUN sed -i 's/redirectPort="8443" \/>/redirectPort="8443"\/><Connector port="8443" protocol="HTTP\/1.1" SSLEnabled="true" maxThreads="150" scheme="https" secure="true" sslProtocol="TLS" keystoreFile="\/opt\/cas\/tomcat.jks" keystorePass="password" truststoreFile="\/opt\/cas\/tomcat.jks" truststorePass="password" clientAuth="true"\/>/' $CATALINA_HOME/conf/server.xml

RUN mkdir -p /opt/cas/conf
RUN mkdir -p /opt/cas/conf/services
RUN mkdir -p /opt/cas/conf/saml
     
COPY tomcat.jks /opt/cas/

COPY cieid*war $CATALINA_HOME/webapps/cieid.war

COPY *.properties /opt/cas/conf/
#COPY services/*.json /opt/cas/conf/services/
COPY saml/* /opt/cas/conf/saml/

COPY *.pem /tmp/

COPY startup.sh /sbin
RUN chmod 755 /sbin/startup.sh
CMD ["/sbin/startup.sh"]
