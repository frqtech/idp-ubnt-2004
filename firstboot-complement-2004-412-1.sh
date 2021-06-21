#!/bin/bash

#title          firstboot-complement-1804-333-1.sh
#description    Complement script for CAFe IDP firstboot.sh
#author         Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date           2021/05/02
#version        2.0.0
#
#changelog      1.0.0 - 2018/10/18 - Initial version for Ubuntu 18.04.
#changelog      1.0.1 - 2019/07/12 - Adequation of certificate generation considering the new package version. 
#changelog      1.0.2 - 2019/07/31 - Added SIRTFI pre-configuration and corrected directory permissions.
#changelog      1.0.2 - 2019/07/31 - Correcao do path do java jre.
#changelog      1.0.2 - 2019/07/31 - Correcao da permissao do idp.key e idp.crt para 644.
#changelog      1.0.2 - 2019/07/31 - Added F-Ticks pre-configuration and corrected directory permissions.
#changelog      1.0.3 - 2020/01/27 - Added scapes for rsyslog.conf file.
#changelog      1.0.4 - 2020/02/06 - General improvement in rsyslog.conf file.
#changelog      1.0.4 - 2020/02/06 - General improvement in rsyslog.conf file.
#changelog      2.0.0 - 2021/05/02 - Initial version for Ubuntu 20.04.

#
# COLETA DE DADOS
#
        if [ -z ${IFILE} ] ; then

            stty sane
    
            #DIRETORIO
            MSG1="Este instalador suporta dois tipos de servidor de diretório:"
            MSG2="Qual o diretório utilizado pela instituição?"
            CMP="tipo de diretório"
            OPT1="AD"
            OPT2="LDAP"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            DIRETORIO="${RET}"

            if [ ${DIRETORIO} -eq 1 ] ; then
                MSG="Digite o dominio AD que será utilizado (ex.: ad.instituicao.br):"
                CMP="dominio AD"
                ler "$MSG" "$CMP"
                confirma "$CMP" "$RET" "$MSG"
                LDAPADDOMAIN="$RET"
            else
                LDAPADDOMAIN=""
            fi

            MSG="Digite o endereco do servidor de diretório (ex.: dc01.ad.instituicao.br ou ldap1.instituicao.br):"
            CMP="endereço do servidor de diretório"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPSERVER="$RET"
            
            MSG="Digite a porta do servidor de diretório (ex.: 389):"
            CMP="porta servidor de diretório"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPSERVERPORT=$RET
            
            MSG1="Escolha uma das opões com relação a configuração de SSL do servidor de diretório:"
            MSG2="O diretório indicado utiliza SSL?"
            CMP="uso de SSL"
            OPT1="Utiliza SSL"
            OPT2="Não utiliza SSL"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            LDAPSERVERSSL=$RET
            
            MSG="Digite o DN para consulta no servidor de diretório (ex.: CN=Users,DC=instituicao,DC=br e ou=People,dc=instituicao,dc=br):"
            CMP="DN"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPDN=$RET
            
            MSG="Digite o DN do usuários de leitura no servidor de diretório (ex.: conta_servico@instituicao.br ou cn=leitor-shib,dc=instituicao,dc=br):"
            CMP="DN do usuários de leitura"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPUSER=$RET
            
            MSG="Digite a senha do usuário de leitura do servidor de diretório:"
            CMP="senha"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPPWD=$RET
            
            # Dados Gerais
            echo ""
            
            MSG="Digite o nome do contato tecnico do servico (ex.: Joao da Silva):"
            CMP="nome do contato tecnico"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CONTACT=$RET
            
            MSG="Digite o e-mail do contato tecnico do servico (ex.: joao.silva@instituicao.br):"
            CMP="e-mail"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CONTACTMAIL=$RET
            
            MSG="Digite o nome da instituicao por exetenso (ex.: Rede Nacional de Ensino e Pesquisa):"
            CMP="nome da instituicao"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            ORGANIZATION=$RET

            MSG="Digite a sigla da instituicao (ex.: RNP):"
            CMP="nome da instituicao"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            INITIALS=$RET

            MSG="Digite o endereco do site da instituicao (ex.: www.instituicao.br):"
            CMP="endereco do site"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            URL=$RET

            MSG="Digite o dominio da instituicao (ex.: instituicao.br):"
            CMP="dominio"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            DOMAIN=$RET
            
            MSG="Digite o nome departamento da instituicao que eh responsavel por este servico (ex.: CPD):"
            CMP="departamento"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            OU=$RET
            
            MSG="Digite o nome da cidade onde esta sediada a instituicao (ex.: Porto Alegre):"
            CMP="cidade"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CITY=$RET
            
            MSG="Digite por extenco o nome da Unidade Federativa onde esta sediada a instituicao (ex.: Rio Grande do Sul):"
            CMP="Unidade Federativa"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            STATE=$RET

            if [ ${DIRETORIO} -eq 1 ] ; then
                LDAPATTR="sAMAccountName"
                LDAPFORM="%s@${LDAPADDOMAIN}"
                LDAPSUBTREESEARCH="true"
            else
                LDAPATTR="uid"
                LDAPFORM="${LDAPATTR}=%s,${LDAPDN}"
                LDAPSUBTREESEARCH="true"
            fi

            if [ ${LDAPSERVERSSL} -eq 1 ] ; then
                LDAPSERVERSSLUSE="true"
                LDAPSERVERPROTO="ldaps://"
            else
                LDAPSERVERSSLUSE="false"
                LDAPSERVERPROTO="ldap://"
            fi

            PERSISTENTDIDSALT=`openssl rand -base64 32`
            COMPUTEDIDSALT=`openssl rand -base64 32`
            FTICKSSALT=`openssl rand -base64 32`

        fi

#
# DEBUG
#
        if [ ${DEBUG} -eq 1 ] ; then
            echo "### FIRSTBOOT COMPLEMENT - INFORMACOES DE DEBUG ###" | tee -a ${F_DEBUG}
            echo "" | tee -a ${F_DEBUG}
            echo "Variáveis lidas:" | tee -a ${F_DEBUG}
            echo "DIRETORIO        = ${DIRETORIO}" | tee -a ${F_DEBUG}
            echo "LDAPADDOMAIN     = ${LDAPADDOMAIN}" | tee -a ${F_DEBUG}
            echo "LDAPSERVER       = ${LDAPSERVER}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERPORT   = ${LDAPSERVERPORT}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERSSL    = ${LDAPSERVERSSL}" | tee -a ${F_DEBUG} 
            echo "LDAPSERVERSSLUSE = ${LDAPSERVERSSLUSE}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERPROTO  = ${LDAPSERVERPROTO}" | tee -a ${F_DEBUG}
            echo "LDAPDN           = ${LDAPDN}" | tee -a ${F_DEBUG}
            echo "LDAPUSER         = ${LDAPUSER}" | tee -a ${F_DEBUG}
            echo "LDAPPWD          = ${LDAPPWD}" | tee -a ${F_DEBUG}
            echo "CONTACT          = ${CONTACT}" | tee -a ${F_DEBUG}
            echo "CONTACTMAIL      = ${CONTACTMAIL}" | tee -a ${F_DEBUG}
            echo "ORGANIZATION     = ${ORGANIZATION}" | tee -a ${F_DEBUG}
            echo "INITIALS         = ${INITIALS}" | tee -a ${F_DEBUG}
            echo "URL              = ${URL}" | tee -a ${F_DEBUG}
            echo "DOMAIN           = ${DOMAIN}" | tee -a ${F_DEBUG}
            echo "OU               = ${OU}" | tee -a ${F_DEBUG}
            echo "CITY             = ${CITY}" | tee -a ${F_DEBUG}
            echo "STATE            = ${STATE}" | tee -a ${F_DEBUG}
            echo "COMPUTEDIDSALT   = ${COMPUTEDIDSALT}" | tee -a ${F_DEBUG}
            echo "PERSISTENTDIDSALT= ${PERSISTENTDIDSALT}" | tee -a ${F_DEBUG}
            echo "FTICKSSALT       = ${FTICKSSALT}" | tee -a ${F_DEBUG}
        fi

#
# PACOTES
#
        apt install -y apache2 libapache2-mod-xforward jetty9

#
# OPENSSL - arquivo de config
#
        cat > /tmp/openssl.cnf <<-EOF
[ req ]
default_bits = 2048 # Size of keys
string_mask = nombstr # permitted characters
distinguished_name = req_distinguished_name
  
[ req_distinguished_name ]
# Variable name   Prompt string
#----------------------   ----------------------------------
0.organizationName = Nome da universidade/organização
organizationalUnitName = Departamento da universidade/organização
emailAddress = Endereço de email da administração
emailAddress_max = 40
localityName = Nome do município (por extenso)
stateOrProvinceName = Unidade da Federação (por extenso)
countryName = Nome do país (código de 2 letras)
countryName_min = 2
countryName_max = 2
commonName = Nome completo do host (incluíndo o domínio)
commonName_max = 64
  
# Default values for the above, for consistency and less typing.
# Variable name   Value
#------------------------------   ------------------------------
0.organizationName_default = ${INITIALS} - ${ORGANIZATION}
emailAddress_default = ${CONTACTMAIL}
organizationalUnitName_default = ${OU}
localityName_default = ${CITY}
stateOrProvinceName_default = ${STATE}
countryName_default = BR
commonName_default = ${HN}.${HN_DOMAIN}
EOF

#
# SHIB - ldap-properties
#
        cat > ${SRCDIR}/conf/ldap.properties <<-EOF
# LDAP authentication (and possibly attribute resolver) configuration
# Note, this doesn't apply to the use of JAAS authentication via LDAP

## Authenticator strategy, either anonSearchAuthenticator, bindSearchAuthenticator, directAuthenticator, adAuthenticator
idp.authn.LDAP.authenticator                    = bindSearchAuthenticator

## Connection properties ##
idp.authn.LDAP.ldapURL                          = ${LDAPSERVERPROTO}${LDAPSERVER}:${LDAPSERVERPORT}
idp.authn.LDAP.useStartTLS                      = false
# Time in milliseconds that connects will block
#idp.authn.LDAP.connectTimeout                  = PT3S
# Time in milliseconds to wait for responses
#idp.authn.LDAP.responseTimeout                 = PT3S
# Connection strategy to use when multiple URLs are supplied, either ACTIVE_PASSIVE, ROUND_ROBIN, RANDOM
#idp.authn.LDAP.connectionStrategy              = ACTIVE_PASSIVE

## SSL configuration, either jvmTrust, certificateTrust, or keyStoreTrust
idp.authn.LDAP.sslConfig                        = certificateTrust
## If using certificateTrust above, set to the trusted certificate's path
idp.authn.LDAP.trustCertificates                = %{idp.home}/credentials/ldap-server.crt
## If using keyStoreTrust above, set to the truststore path
#idp.authn.LDAP.trustStore                      = %{idp.home}/credentials/ldap-server.truststore

## Return attributes during authentication
idp.authn.LDAP.returnAttributes                 = ${LDAPATTR}

## DN resolution properties ##

# Search DN resolution, used by anonSearchAuthenticator, bindSearchAuthenticator
# for AD: CN=Users,DC=example,DC=org
idp.authn.LDAP.baseDN                           = ${LDAPDN}
idp.authn.LDAP.subtreeSearch                    = ${LDAPSUBTREESEARCH}
idp.authn.LDAP.userFilter                       = (${LDAPATTR}={user})
# bind search configuration
# for AD: idp.authn.LDAP.bindDN=adminuser@domain.com
idp.authn.LDAP.bindDN                           = ${LDAPUSER}

# Format DN resolution, used by directAuthenticator, adAuthenticator
# for AD use idp.authn.LDAP.dnFormat=%s@domain.com
idp.authn.LDAP.dnFormat                         = ${LDAPFORM}

# pool passivator, either none, bind or anonymousBind
#idp.authn.LDAP.bindPoolPassivator              = none

# LDAP attribute configuration, see attribute-resolver.xml
# Note, this likely won't apply to the use of legacy V2 resolver configurations
idp.attribute.resolver.LDAP.ldapURL             = %{idp.authn.LDAP.ldapURL}
idp.attribute.resolver.LDAP.connectTimeout      = %{idp.authn.LDAP.connectTimeout:PT3S}
idp.attribute.resolver.LDAP.responseTimeout     = %{idp.authn.LDAP.responseTimeout:PT3S}
idp.attribute.resolver.LDAP.connectionStrategy  = %{idp.authn.LDAP.connectionStrategy:ACTIVE_PASSIVE}
idp.attribute.resolver.LDAP.baseDN              = %{idp.authn.LDAP.baseDN:undefined}
idp.attribute.resolver.LDAP.bindDN              = %{idp.authn.LDAP.bindDN:undefined}
idp.attribute.resolver.LDAP.useStartTLS         = %{idp.authn.LDAP.useStartTLS:true}
idp.attribute.resolver.LDAP.trustCertificates   = %{idp.authn.LDAP.trustCertificates:undefined}
idp.attribute.resolver.LDAP.searchFilter        = (${LDAPATTR}=$resolutionContext.principal)

# LDAP pool configuration, used for both authn and DN resolution
#idp.pool.LDAP.minSize                          = 3
#idp.pool.LDAP.maxSize                          = 10
#idp.pool.LDAP.validateOnCheckout               = false
#idp.pool.LDAP.validatePeriodically             = true
#idp.pool.LDAP.validatePeriod                   = PT5M
#idp.pool.LDAP.validateDN                       =
#idp.pool.LDAP.validateFilter                   = (objectClass=*)
#idp.pool.LDAP.prunePeriod                      = PT5M
#idp.pool.LDAP.idleTime                         = PT10M
#idp.pool.LDAP.blockWaitTime                    = PT3S 
EOF

#
# SHIB - idp-properties
#
        cat  > ${SRCDIR}/conf/idp.properties <<-EOF
EOF

#
# SHIB - saml-nameid-properties
#
        cat  > ${SRCDIR}/conf/saml-nameid.properties <<-EOF
EOF

#
# SHIB - secrets.properties
#
        cat  > ${SRCDIR}/conf/credentials/secrets.properties <<-EOF
# Access to internal AES encryption key
#idp.sealer.storePassword = changeit
#idp.sealer.keyPassword = changeit

# Default access to LDAP authn and attribute stores.
idp.authn.LDAP.bindDNCredential              = ${LDAPPWD}
idp.attribute.resolver.LDAP.bindDNCredential = %{idp.authn.LDAP.bindDNCredential:undefined}

# Salt used to generate persistent/pairwise IDs, must be kept secret
idp.persistentId.salt  = ${PERSISTENTDIDSALT}

idp.cafe.computedIDsalt = ${COMPUTEDIDSALT}
EOF

#
# APACHE - config site, modules e certificados - 01-idp.conf
#
        cat > /etc/apache2/sites-available/01-idp.conf <<-EOF
<VirtualHost ${IP}:80>

    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}
    ServerSignature Off
    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    Redirect permanent "/" "https://${HN}.${HN_DOMAIN}/"

</VirtualHost>

<VirtualHost ${IP}:443>
 
    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}
    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log
 
    SSLEngine On
    SSLProtocol -all +TLSv1.1 +TLSv1.2
    SSLCipherSuite ALL:+HIGH:+AES256:+GCM:+RSA:+SHA384:!AES128-SHA256:!AES256-SHA256:!AES128-GCM-SHA256:!AES256-GCM-SHA384:-MEDIUM:-LOW:!SHA:!3DES:!ADH:!MD5:!RC4:!NULL:!DES
    SSLHonorCipherOrder on
    SSLCompression off
    SSLCertificateKeyFile /etc/ssl/private/chave-apache.key
    SSLCertificateFile /etc/ssl/certs/certificado-apache.crt
 
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port 443
    ProxyPass /idp http://localhost:8080/idp
    ProxyPassReverse /idp http://localhost:8080/idp

    Redirect permanent "/" "https://${URL}/"

</VirtualHost>
EOF

        # Chave e Certificado Apache
        openssl genrsa -out /etc/ssl/private/chave-apache.key 2048
        openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key /etc/ssl/private/chave-apache.key -set_serial 00 \
            -config /tmp/openssl.cnf -out /etc/ssl/certs/certificado-apache.crt
        if [ ${DEBUG} -eq 1 ] ; then
            echo "" 
            echo "Certificado Apache" | tee -a ${F_DEBUG}
            openssl x509 -in /etc/ssl/certs/certificado-apache.crt -text -noout >> /root/cafe-firstboot.debug | tee -a ${F_DEBUG}
        fi
        chown root:ssl-cert /etc/ssl/private/chave-apache.key /etc/ssl/certs/certificado-apache.crt
        chmod 640 /etc/ssl/private/chave-apache.key

        a2dissite 000-default.conf
        a2enmod ssl headers proxy_http
        a2ensite 01-idp.conf
        systemctl restart apache2

#
# CAFE - Personalização layout
#

#
# FTICKS - Filebeat / rsyslog
#

#
# FAIL2BAN
#

#
# SHIB - Instalação
#

#
# OpenSSL - Geração de certificados shib
#

#
# SHIB - Ajuste arquivo de metadados
#

#
# KEYSTORE - Popular com certificados
#
#TODO: Tratar certificados AD

        # Se LDAP usa SSL, pega certificado e adiciona no keystore
        if [ ${LDAPSERVERSSL} -eq 1 ] ; then
            openssl s_client -showcerts -connect ${LDAPSERVER}:${LDAPSERVERPORT} < /dev/null 2> /dev/null | openssl x509 -outform PEM > /opt/shibboleth-idp/credentials/ldap-server.crt
            /usr/lib/jvm/java-11-amazon-corretto/bin/keytool -import -alias ldap.local -keystore /usr/lib/jvm/java-11-amazon-corretto/lib/security/cacerts -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit
        fi

#
# JETTY - Configuração
#
        sed -i 's/^ReadWritePaths=\/var\/lib\/jetty9\/$/ReadWritePaths=\/var\/lib\/jetty9\/ \/opt\/shibboleth-idp\/credentials\/ \/opt\/shibboleth-idp\/logs\/ \/opt\/shibboleth-idp\/metadata\//' /lib/systemd/system/jetty9.service
        systemctl daemon-reload

        # Corrige permissões
        chown -R jetty:jetty /opt/shibboleth-idp/{credentials,logs,metadata}

        # Configura contexto no Jetty
        cat > /var/lib/jetty9/webapps/idp.xml <<-EOF
<Configure class="org.eclipse.jetty.webapp.WebAppContext">
  <Set name="war">/opt/shibboleth-idp/war/idp.war</Set>
  <Set name="contextPath">/idp</Set>
  <Set name="extractWAR">false</Set>
  <Set name="copyWebDir">false</Set>
  <Set name="copyWebInf">true</Set>
  <Set name="persistTempDirectory">false</Set>
</Configure>
EOF
