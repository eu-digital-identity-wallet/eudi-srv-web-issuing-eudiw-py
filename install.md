# Installation

## 1. Python

The EUDIW Issuer was tested with

+ Python version 3.9.2

and should only be used with Python 3.9 or 3.10.

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The EUDIW Issuer was tested with

+ Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).

## 3. How to run the EUDIW Issuer?

To run the EUDIW Issuer, please follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.


1. Clone the EUDIW Issuer repository:

    ```shell
    git clone git@github.com:eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py.git
    ```

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudi-srv-web-issuing-eudiw-py
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```


4. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```


5. Install Flask, gunicorn and other dependencies in virtual environment

    ```shell
    pip install -r app/requirements.txt
    ```

6. Setup secrets
   
   -  Copy ```app/app_config/__config_secrets.py``` to ```app/app_config/config_secrets.py``` and modify secrets.

7. Service Configuration

   - Configure the service according to [documentation](api_docs/configuration.md)  

8. Run the EUDIW Issuer 

    On the root directory of the clone repository, insert one of the following command lines to run the EUDIW Issuer.

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000>)

    ```
    flask --app app run
    ```

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000> with flag debug)

    ```
    flask --app app run --debug
    ```
    
## 4. Running your local EUDIW Issuer over HTTPS

1. Generate a self signed certificate and a private key
   + Linux/macOS
     
       Example: 
        ```
        openssl req -x509 -out localhost.crt -keyout localhost.key -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <( \
       printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=IP.1:127.0.0.1\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
        ```

    + Windows

        Create the file localhost.conf using the following as an example:
        ```
        [req]
        default_bits  = 2048
        distinguished_name = req_distinguished_name
        req_extensions = req_ext
        x509_extensions = v3_req
        prompt = no
        [req_distinguished_name]
        countryName = XX
        stateOrProvinceName = N/A
        localityName = N/A
        organizationName = Self-signed certificate
        commonName = 120.0.0.1: Self-signed certificate
        [req_ext]
        subjectAltName = @alt_names
        [v3_req]
        subjectAltName = @alt_names
        [alt_names]
        IP.1 = 127.0.0.1
        ```

        Use the configuration file above to generate the certificate and key
        ```
        openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout key.pem -out cert.pem -config localhost.conf 
        ```
        
2. Add certificate to environment variables
   + Linux/macOS
       ```
        export REQUESTS_CA_BUNDLE="/path/to/certificate"
       ```
  
   + Windows
        ```
        set REQUESTS_CA_BUNDLE="\path\to\certificate"
        ```
  
3. Run the EUDIW Issuer with certificate and key
    ```
    flask --app app run --cert=cert.pem --key=key.pem
    ```
    
## 5. Make your local EUDIW Issuer available on the Internet (optional)

If you want to make your local EUDIW Issuer available on the Internet, we recommend to use NGINX reverse proxy and certbot (to generate an HTTPS certificate).

### 5.1 Install and configure NGINX

1. Follow the installation guide in https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/

2. Configure your local EUDIW Issuer. For example, use the following Nginx configuration file (for a Linux installation):

```nginx
server {
    server_name FQDN; # Change to the FQDN you want to use

    listen 80;
    access_log /var/log/nginx/issuer.eudiw.access.log;
    error_log /var/log/nginx/issuer.eudiw.error.log;
    root /var/www/html;

# Recommended
    proxy_busy_buffers_size   512k;
    proxy_buffers   4 512k;
    proxy_buffer_size   256k;

# Provider backend
    location / {
        # The proxy_pass directive assumes that your local EUDIW Issuer is running at http://127.0.0.1:5000/. 
        # If not, please adjust it accordingly.
        proxy_pass                              http://127.0.0.1:5000/;
        proxy_set_header Host                   $http_host;
        proxy_set_header X-Real-IP              $remote_addr;
        proxy_set_header X-Forwarded-For        $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto      $scheme;
    }
}
```

3. Restart the Nginx server


### 5.2 Install and run certbot to gef a free HTTPS certificate

1. Follow the installation guide in https://certbot.eff.org

2. Run `certbot` to get a free HTTPS certificate. The `certbot` will also configure the EUDIW Issuer Nginx configuration file with the HTTPS certificate.

3. Restart the Nginx server and goto `https:\\FQDN\` (FQDN configured in the Nginx configuration file)


## 6. Docker

To run the EUDIW issuer in Docker please follow these steps:

1. Install Docker following the official instructions for your operating system : <https://docs.docker.com/engine/install/>

2. Download the Dockerfile at <https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/blob/main/Dockerfile> 

3. Build the Docker: `sudo docker build -t eudiw-issuer .`

4. Create 2 directories to be mounted:

   1. First directory named `config_secrets`
      
      This directory will have the cert.pem and key.pem generated in [Section 4](#4-running-your-local-eudiw-issuer-over-https)
   
      As well as the config_secrets.py based on this [example](app/app_config/__config_secrets.py)


   2. Second directory named `pid-issuer`, inside will be a directory `cert` and `privKey`
      
      The `cert` directory has the certificates of the trusted CAs in PEM format as well as the Document/Credential signer (DS) certificates in DER format

      The `privKey` directory has the Document/Credential signer (DS) private keys


    Example:
   

    ```bash
    docker-issuer
    ├── Dockerfile
    ├── config_secrets
    │   ├── config_secrets.py
    │   ├── cert.pem
    │   └── key.pem
    └── pid-issuer
        ├── cert
        │   ├── PID-DS-0001_UT_cert.der
        │   └── PIDIssuerCAUT01.pem
        └── privKey
            └── PID-DS-0001_UT.pem
    ```

5. Run Docker

    If running a basic configuration without EIDAS node or Dynamic presentation, their respective variables can be removed from the run command below.
    
    ```bash
    sudo docker run -d \
    --name eudiw-issuer \
    -e SERVICE_URL="https://your.service.url/" \
    -e EIDAS_NODE_URL="https://your.eidas.node.url/" \
    -e DYNAMIC_PRESENTATION_URL="https://your.dynamic.presentation.url/" \
    -v ./config_secrets:/root/secrets \
    -v ./pid-issuer:/etc/eudiw/pid-issuer \
    -p 5000:5000 \
    eudiw-issuer
    ```

5. Docker logs

    Issuer logs in real time: `sudo docker logs -f eudiw-issuer`
    All logs: `sudo docker logs eudiw-issuer`

6. Stopping Docker Issuer
   `sudo docker stop eudiw-issuer`


