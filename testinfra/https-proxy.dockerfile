FROM nginx:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install openssl

RUN printf '.\n.\n.\n.\n.\n%s\n.\n' "testserver-https.example.com" | openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem -days 365 && \
    printf 'server {\n\tlisten 443 ssl;\n\t\n\tserver_name %s.example.com;\n\tssl_certificate /etc/nginx/cert.pem;\n\tssl_certificate_key /etc/nginx/key.pem;\n\tlocation / {\n\t\tproxy_pass http://%s.example.com:80;\n\t}\n}' "testserver-https" "testserver-http" > /etc/nginx/conf.d/vhost.conf

EXPOSE 443

