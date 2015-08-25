# At-Rest Encryption

At-Rest Encryption is a module for OpenStack Swift, buit over [CDMI API](https://github.com/osaddon/cdmi). It extends CDMI API to add server-side encryption and decricryption of data. Data gets encrypted inside Swift cluster with an AES-256 Key. 

## Usage
In order to use At-Rest Encryption, it's necessary to add a 'X-AES-Key' header to each upload and download request that data is intended to be encrypted or decrypted. This header contains the encryption key and looks like:
  - X-AES-Key: Some_key

If the key is provided, when uploading a file, this file will be encrypted and stored. When downloading it, it's possible to provide a key to decrypt it and download it in 'plain text' or, if no key is provided, the encrypted copy of the file will be downloaded.

## Installation
First of all, it's necessary to download/clone the repository. Move to the project folder and run the following commands with **root privileges**:
### 1. Move the source files to the destination
Copy and paste the following code:

    # Go to the src directory.
    cd src/
    # Copy the encryption.py and decruption.py to its destination
    cp -v *.py /usr/lib/python2.7/dist-packages/swift/common/middleware/

### 2. Append the entry points for the Middeware
Copy and paste the following code:

    #Add encrypter endpoint
    echo "encrypter = swift.common.middleware.encrypter:filter_factory" >> /usr/lib/python2.7/dist-packages/swift-2.2.0.egg-info/entry_points.txt
    #Add decrypter endpoint
    echo "decrypter = swift.common.middleware.decrypter:filter_factory" >> /usr/lib/python2.7/dist-packages/swift-2.2.0.egg-info/entry_points.txt
    
### 3. Configure the Proxy
Edit the proxy configuration file with your favourite editor (example with vim):

    vim /etc/swift/proxy-server.conf
    
Go to the line that should look like:

    pipeline = gatekeeper catch_errors keystone ... cdmi proxy-server
Add between your authentication driver and before cdmi in the pipeline string "encrypter" and "decrypter". It should look like:

    pipeline = gatekeeper catch_errors cache healthcheck keystone ... encrypter decrypter cdmi proxy-server
    
Please note that depending on the installed modules, the pipeline can be slightly different. The gatekeeper, catch_errors, cache and healhcheck modules are required. 

Finally, append before the [filter:cdmi] section, the following:
    [filter:decrypter]
    use = egg:swift#decrypter
    
    [filter:encrypter]
    use = egg:swift#encrypter
    
### 4. Restart Services
When you reach this point, the installation is done! Now just have to restart swift proxy to enable the module:

    sudo service swift-proxy restart

The output should provide no errors. If there are errors, please see section debugging.


    

## Limitations
- The encryption key cannot contain spaces.
- CDMI API is necessary, althought with some tweaks it can scape this limitation :)


## Version
1.0.1

## Debugging
If the installation failed (for any resason) or there's a missconfiguration and you can't start the proxy server please, do the following:
 
    sudo swift-init proxy restart
    
This will show the stacktrace and will help you to know where the error comes from. If you need further help, don't heasitate to contact me at roig.alex@gmail.com

## License
This software is distributed as-is withoud any warranty. It's licensed under Apache 2.0.