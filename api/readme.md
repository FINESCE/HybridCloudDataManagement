# CDMI-SWIFT DSE CUSTOM API
CDMI-SWIFT DSE CUSTOM API is an API build over CDMI using Laravel 4.2 that provides a simplified interface to access Swift data. It integrates with [Seamless Authentication](http://example.org/replace) and [At-Rest Encryption](http://example.org/replace)

## Why to use it?
This API provies a simplified way to interact with Swift using a simple interface that can be integrated easily with any webpage or client. Requests are configurable and all methods are supported so that using GET requests, most operations (except upload) can be performed, so that integrating with a webpage is very easy; no custom headers are needed like X-Auth-Token

## Usage
The API provides several methods to perform actions to Swift.
### - Authenticate
This method is used to authenticate and retrieve the auth and token. Auth is the name of the root container and the token authorizes the requests.
- Methods allowed: **GET**, POST
- Endpoint: /api/authenticate
- Parameters:
    - username: string
    - password: string
    - host (optional): ip:port. Overrides the default host configuration on the API.
- Typical response code: 200
- Typical response body:

        {
            "token": "3a0842b29340d1b7f82971721090addf",
            "auth_url": "http://controller:8080/v1/AUTH_00000000000000000000000000008206",
            "auth": "AUTH_00000000000000000000000000008206"
        }
### - List

This method lists a directory contents. Is the "equivalent" of ls command in unix systems.
- Methods allowed: **GET**, POST
- Endpoint /api/list
- Parameters:
    - token: string
    - auth: string
    - container (optional): string. Path to the container to be listed. If not present, the root container is listed. Never start the path with /
    - host (optional): ip:port. Same as authentication.
- Typical response code: 200
- Typical response body:

        {
            "items": [
                "folder0/",
                "folder1/",
                "folder2/",
                "file1",
                "file2",
                "file3"
            ]
        }
        
### - Create

This method allows to create a container or subcontainer. It's the equivalent of mkdir in a unix system.
- Methods allowed: **GET**, POST
- Endpoint /api/create
- Parameters:
    - token: string
    - auth: string
    - container: string. Path to the container to be created (includint it). Never start the path with /. To create a container in the root-container, the param should be (myFolder). To create a container inside the just created, the param should be (myFolder/myNewFolder).
    - host (optional): ip:port. Same as authentication.
- Typical response code: 201
- Typical response body:

        {“status”:“ok”}
        
### - Delete

This method allows to delete a container, subcontainer or file. It's the equivalent of rm or rmdir in a unix system.
- Methods allowed: **GET**, POST, DELETE
- Endpoint /api/delete
- Parameters:
    - token: string
    - auth: string
    - container: string. Path to the file or container to be deleted. Never start with /.
    - host (optional): ip:port. Same as authentication.
- Typical response code: 200
- Typical response body:

        {“status”:“ok”}
        
### - Download

This method allows to download a file from Swift.
- Methods allowed: **GET**
- Endpoint /api/download
- Parameters:
    - token: string
    - auth: string
    - container: string. Path to the container where the desired file is. Never start with /.
    - object: string. Name of the file to download.
    - key (optional): string. Encryption key. Only if using At-Rest Encryption.
    - host (optional): ip:port. Same as authentication.
- Typical response code: 200
- Typical response body:

        data stream
        
### - Upload

This method allows to download a file from Swift.
- Methods allowed: **PUT**
- Endpoint /api/upload
- Parameters:
    - token: string
    - auth: string
    - container: string. Path to the container to be upload. Never start with /.
    - object: string. Name of the file to upload.
    - key (optional): string. Encryption key. Only if using At-Rest Encryption.
    - host (optional): ip:port. Same as authentication.
- Request body: the file to be uploaded
- Typical response code: 200
- Typical response body:

        “status”:“created”}

## System Requirements

- Git (apt-get install git)
- [Laravel Prerequisites](http://laravel.com/docs/4.2/installation)
    - Apache2 (apt-get install apache2)
    - Apache2 mod-rewrite
    - Apache2 mod-ssl
    - PHP 5 (apt-get install php5)
    -  [Composer](https://getcomposer.org/download/) - Make a global installation
    - PHP5-Mcrypt (apt-get install php5-mcrypt)
    - PHP5-mysql (apt-get install php5-mysql)
    - PHP5-curl (apt-get install php5-curl)

## Installation
First of all, it's necessary to download/clone the repository. We recommend to clone it into /var/www. After cloning, it will appear a api folder that contains the project, if it has another name, plese, rename it. Move to that folder to continue. Move to the project folder and run the following commands with **root privileges**:
### 1. Check Permissions
Make sure that the user owner of the project files is the same as apache (normally www-data, it can vary depending on Linux distribution)

    cd /var/www
    sudo chown -R www-data:www-data api
    cd api
    sudo chmod 777 app/storage

### 2. Install Dependencies
Copy and paste the following code:

    cd /var/www/api
    sudo composer update
The output shouldn't have errors. It can produce some warnings which you can safefly ignore them.
    
### 3. Configure API and Swift
Installation can be performed on the same host that has a Swift proxy or in another. The default configuration assumes that the host contains the API and swift.

    vim app/controllers/ApiController.php
    # goto line #4
    private $host = "localhost:9443"; -> replace for the hostname or ip and desired port.

If both services are running on the same machine, make sure that Swift isn't running at port 80 and/or 443, because Apache will use them. If that's the case, we should configure another port for swift. It can be done editing:
    
    /etc/swift/proxy-server.conf
    
Find and edit or create a line that contains:
    bind-port = 9443 # or desired port. It must match the one set on the API!
    
### 4. Configure Apache
Virtual Hosts or base apache configuration is necessary. We used the following example. If paths aren't exactly the same as the file, plese, edit the file accordingly. Plese, replace yourservername for the hostname your server.
    
    <VirtualHost *:80>
      ServerName yourservername
    
      ## Vhost docroot
      DocumentRoot "/var/www/api/public"
    
      ## Directories, there should at least be a declaration for /var/www/api/public
    
      <Directory "/var/www/api/public">
        Options Indexes FollowSymlinks MultiViews
        AllowOverride All
        Require all granted
    
      </Directory>
    
      ## Load additional static includes
    
      ## Logging
      ErrorLog "/var/log/apache2/tnvxxovljm9x_error_ssl.log"
      ServerSignature Off
      CustomLog "/var/log/apache2/tnvxxovljm9x_access_ssl.log" combined

      ## Server aliases
      ServerAlias www.yourservername
    
      ## SetEnv/SetEnvIf for environment variables
      SetEnv APP_ENV dev
    
      
    </VirtualHost>
    
    <VirtualHost *:443>
      ServerName yourservername
    
      ## Vhost docroot
      DocumentRoot "/var/www/api/public"

      ## Directories, there should at least be a declaration for /var/www/api/public
      
      <Directory "/var/www/api/public">
        Options Indexes FollowSymlinks MultiViews
        AllowOverride All
        Require all granted
    
      </Directory>
    
      ## Load additional static includes
    
      ## Logging
      ErrorLog "/var/log/apache2/tnvxxovljm9x_error_ssl.log"
      ServerSignature Off
      CustomLog "/var/log/apache2/tnvxxovljm9x_access_ssl.log" combined
    
      ## Server aliases
      ServerAlias www.yourservername
    
      ## SetEnv/SetEnvIf for environment variables
      SetEnv APP_ENV dev
    
      ## SSL directives
      SSLEngine on
      SSLCertificateFile      "/etc/ssl/certs/ssl-cert-snakeoil.pem" # replace with your cert if ssl is needed
      SSLCertificateKeyFile   "/etc/ssl/private/ssl-cert-snakeoil.key" # replace with your key if ssl is needed
      SSLCACertificatePath    "/etc/ssl/certs"

    </VirtualHost>


## Configuration
Default configuration of the module should work, but, if something changes on the FiWare Lab, the endpoints and other configuration can be overrided in the /etc/swift/proxy-server.conf, at section [filter:customauth]. The following list shows the configurable items and it's default value:

    reseller_prefix = AUTH
    organization_id = "57...a8" # Change it for your own organization that authorizes access!
    keystone_auth_endpoint = http://cloud.lab.fiware.org:4730/v2.0/tokens
    keystone_tenant_endpoint = http://cloud.lab.fiware.org:4730/v2.0/tenants

This data can also be modified in the source code, but it's recommended to change it in the config file.

## Limitations
- The default configuration is intended to integrate with [Fiware Lab](https://cloud.lab.fiware.org). Integration with third-party platforms, is not guarranteded.


## Version
1.0.2

## Debugging
Check Laravel Logs (app/storage/logs/laravel.log).

Chech Apache Logs (/var/logs/httpd/access.log and error.log). The exact path depends on the system...
If you need further help, don't heasitate to contact me at roig.alex@gmail.com

## See Also
[At-Rest Encryption](#)
[Seamless Authentication](#)

## License
### Source Code
This software is distributed as-is withoud any warranty. It's licensed under Apache 2.0.

### Dependencies
#### - Laravel
The Laravel framework is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT)
#### - Other
See the license for each specific module/dependency listed in composer.json file.
