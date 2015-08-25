# CustomAuth
CustomAuth is an authentication plugin for OpenStack Swift that proxies all requests to Keystone on Fiware LAB. It catches locally the tokens so that during the validity of the token, the local proxy will validate the X-Auth-Token and the tenant-id.

It's built in the swift's proxy middleware chain and substitudes tempauth or keystoneauth. It's usage is completely transparent as if you were using the native keystone implementation.

In order to implement cache, a memcached server is needed. It can handle multiple memcached servers to implement HA.

## Why to use it?
CustomAuth module allows to use the same security token for storing data in a private cloud and a Public Cloud. Permissions and users are centralized on the public cloud.

Sharing the same token and tenant-id has some advantages: it provides a seamless integration between local and remote and allows the possibility to build simpler clients that can handle multiple storage locations.

## Installation
First of all, it's necessary to download/clone the repository. Move to the project folder and run the following commands with **root privileges**:
### 1. Move the source files to the destination
Copy and paste the following code:

    # Go to the src directory.
    cd src/
    # Copy the customauth.py to its destination
    cp -v *.py /usr/lib/python2.7/dist-packages/swift/common/middleware/

### 2. Append the entry points for the Middeware
Copy and paste the following code:

    #Add customauth endpoint
    echo "customauth = swift.common.middleware.customauth:filter_factory" >> /usr/lib/python2.7/dist-packages/swift-2.2.0.egg-info/entry_points.txt
   
    
### 3. Configure the Proxy
Edit the proxy configuration file with your favourite editor (example with vim):

    vim /etc/swift/proxy-server.conf
    
Go to the line that should look like:

    pipeline = gatekeeper catch_errors keystone ... proxy-server
Replace your authentication driver (keystone or tempauth in most cases) for customauth.It should look like:

    pipeline = gatekeeper catch_errors cache healthcheck customauth ... proxy-server
    
Please note that depending on the installed modules, the pipeline can be slightly different. The gatekeeper, catch_errors, cache and healhcheck modules are required. 

Finally, append before the [filter:cdmi] section if present, the following:
    [filter:customauth]
    use = egg:swift#customauth

    
### 4. Restart Services
When you reach this point, the installation is done! Now just have to restart swift proxy to enable the module:

    sudo service swift-proxy restart

The output should provide no errors. If there are errors, please see section debugging.


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
1.3

## Debugging
If the installation failed (for any resason) or there's a missconfiguration and you can't start the proxy server please, do the following:
 
    sudo swift-init proxy restart
    
This will show the stacktrace and will help you to know where the error comes from. If you need further help, don't heasitate to contact me at roig.alex@gmail.com

## See Also
[At-Rest Encryption](#)
[]
## License
This software is distributed as-is withoud any warranty. It's licensed under Apache 2.0.