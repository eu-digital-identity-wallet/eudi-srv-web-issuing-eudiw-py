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

6. Setup env
   
   -  Copy ```app/.env.example``` to ```app/.env``` and modify variables.

   ```shell
   cp app/.env.example app/.env
   ```

7. Service Configuration

   - Configure the service according to [documentation](api_docs/configuration.md)  

8. Install Authorization Server
    - Install the service according to [Issuer Authorization Server]()

9. Install Issuer Front-End
    - Install the service according to [Issuer Front-End]()

10. Run the EUDIW Issuer Back-end

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

This guide provides step-by-step instructions for deploying the **EUDIW Issuer** service using **Docker Compose v2**.

1. Install docker

    Ensure you have Docker installed on your system. Follow the **official installation instructions** for your operating system:
    [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)


2. Configure Docker Compose

    The service's container orchestration is managed by the `docker-compose.yml` file.

    * **Customize the configuration:** Review and modify the local `docker-compose.yml` file to align with your specific deployment requirements (e.g., exposed ports, service names, volumes).
    * *Reference file:* [docker-compose.yml](./docker-compose.yml)

3. Set Up Environment Variables

    Service parameters and sensitive settings are managed through an environment file.

    * **Create the environment file:** We recommend copying the example file to create your local configuration.

    * **Update variables:** Edit the newly created `app/.env` file with your specific settings and credentials.
        * *Reference example:* [.env example](./app/.env.example)


4. Pull the Docker Image

    ```
    docker compose pull
    ```

5. Run the 

    Start the EUDIW Issuer backend in detached mode (runs in the background):

    ```
    docker compose up -d
    ```

6. Check Logs

    To confirm the service is running correctly and to monitor its output in real-time for troubleshooting, use the following command:
    ```
    docker compose logs -f
    ```

7. Deploy Related Services

To complete the full EUDIW ecosystem, you will also need to deploy the associated Front-end and Authorization Server components.

* **Front-end Installation:** Follow the guide to install the web issuing front-end component using Docker.
    * [Front-end Deployment Guide](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-frontend-eudiw-py/blob/dev/install.md#6-docker)

* **Authorization Server Installation:** Follow the guide to install the OIDC authorization server component using Docker.
    * [Authorization Server Deployment Guide](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-oidc-eudiw-py/blob/dev/install.md#6-docker)