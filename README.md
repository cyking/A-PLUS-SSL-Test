# A-PLUS-SSL-Test
How to get an A+ score on https://www.ssllabs.com/ssltest/ with NGINX & APACHE2 and still work with Android, Java 7, & iOS.

**Requirements:**
* to be as modern and secure as possible
* still support iOS 7.1 & Android 4.04
* still support Java 7u25 & Java v8u31

__last updated:__ 8 March 2015

_______

## A great resource:
* CONFIG GENERATOR:
 
 https://mozilla.github.io/server-side-tls/ssl-config-generator/
* REFERENCE:

  https://wiki.mozilla.org/Security/Server_Side_TLS

## Test your current ssl server test score at:
https://www.ssllabs.com/ssltest/

_______


## NGINX

#### ACTUAL SCORE:
https://www.ssllabs.com/ssltest/analyze.html?d=zingrr.com

Current status:

- [x] Android 4.0.4

- [x] iOS 7.1

- [ ] Java 7u25 <-- working on this currently   



![score](https://github.com/cyking/A-PLUS-SSL-Test/raw/master/screenshots/score_8_march_2015.png "score")

...

![handshake](https://github.com/cyking/A-PLUS-SSL-Test/raw/master/screenshots/handshake_8_march_2015.png "handshake")


#### NGINX requirements:
1. Create a dhparam.pem file for each of your servers.
 
```bash
sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```   


#### NGINX configuration:   

* INSPIRATION:

  https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html


* REFERENCE: 

   https://news.ycombinator.com/item?id=9141701


* NOTE: 

  `includeSubdomains` is used for star certificates. eg: `*.mydomain.com`

  Remove if you have a single domain certificate.

```config
ssl on;

# Diffie-Hellman parameter for DHE ciphersuites, recommended 4096 bits
ssl_dhparam         /etc/nginx/ssl/dhparam.pem;

# certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
ssl_certificate     /etc/nginx/ssl/ssl-unified.crt;
ssl_certificate_key /etc/nginx/ssl/private.key;

ssl_session_timeout 5m;

# modern configuration. tweak to your needs.
ssl_prefer_server_ciphers On;

ssl_session_cache shared:SSL:10m;

ssl_protocols TLSv1 TLSv1.1 TLSv1.2


ssl_ciphers '!ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:!DHE-RSA-AES128-GCM-SHA256:!DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:!ECDHE-RSA-AES128-SHA256:!ECDHE-RSA-AES128-SHA:!ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:!DHE-RSA-AES128-SHA256:!DHE-RSA-AES128-SHA:!DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!AES128-GCM-SHA256:AES256-GCM-SHA384:!AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!AES128-SHA256:!DES-CBC3-SHA:!CAMELLIA128-SHA:!DHE-RSA-CAMELLIA128-SHA';



# HSTS (ngx_http_headers_module is required) Remember this setting for 365 days. include for all subdomains.
add_header Strict-Transport-Security 'max-age=31536000; includeSubdomains';
add_header X-Frame-Options DENY;

 # OCSP Stapling ---
 # fetch OCSP records from URL in ssl_certificate and cache them
 ssl_stapling on;
 ssl_stapling_verify on;
```

```config
# nice and tight, but does not support android / java

ssl_protocols TLSv1.2;

ssl_ciphers '!ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:!DHE-RSA-AES128-GCM-SHA256:!DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:!ECDHE-RSA-AES128-SHA256:!ECDHE-ECDSA-AES128-SHA256:!ECDHE-RSA-AES128-SHA:!ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:!DHE-RSA-AES128-SHA256:!DHE-RSA-AES128-SHA:!DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!AES128-GCM-SHA256:AES256-GCM-SHA384:!AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!AES128-SHA256:!DES-CBC3-SHA:!CAMELLIA128-SHA:!DHE-RSA-CAMELLIA128-SHA';

```
______

## APACHE2

Current status:

- [ ] Android 4.0.4

- [ ] iOS 7.1

- [ ] Java 7u25



#### APACHE2 requirements:

TO DO

#### APACHE2 configuration

*not tested yet*
```config
SSLEngine on
SSLCertificateFile      /path/to/signed_certificate
SSLCertificateChainFile /path/to/intermediate_certificate
SSLCertificateKeyFile   /path/to/private/key
SSLCACertificateFile    /path/to/all_ca_certs

# modern configuration, tweak to your needs
SSLProtocol             TLSv1.2

SSLCipherSuite          !ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:!DHE-RSA-AES128-GCM-SHA256:!DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:!ECDHE-RSA-AES128-SHA256:!ECDHE-RSA-AES128-SHA:!ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:!DHE-RSA-AES128-SHA256:!DHE-RSA-AES128-SHA:!DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!AES128-GCM-SHA256:AES256-GCM-SHA384:!AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!AES128-SHA256:!DES-CBC3-SHA:!CAMELLIA128-SHA:!DHE-RSA-CAMELLIA128-SHA

SSLHonorCipherOrder     on

# HSTS (mod_headers is required) (15768000 seconds = 6 months)
Header always add Strict-Transport-Security "max-age=15768000"
_____

Improvments and discussions are welcomed :smile:
