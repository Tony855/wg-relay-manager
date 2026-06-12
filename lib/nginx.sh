#!/bin/bash

# ===========================================
# Nginx 配置和 SSL 证书管理函数库
# ===========================================

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/utils.sh"

# ============================ Nginx配置函数 ============================

configure_nginx_ssl() {
    info "配置Nginx和SSL..."
    
    stop_nginx
    create_nginx_directories
    configure_ssl_certificates
    configure_nginx_site
    test_and_start_nginx
}

stop_nginx() {
    systemctl stop nginx 2>/dev/null || true
}

create_nginx_directories() {
    mkdir -p $NGINX_CONF_DIR /etc/nginx/snippets /var/www/html
    echo "流量转发中继管理系统" > /var/www/html/index.html
    chmod -R 755 /var/www/html
}

configure_ssl_certificates() {
    if $ENABLE_SSL; then
        if [[ -z "$DOMAIN_NAME" || "$DOMAIN_NAME" == "localhost" ]]; then
            generate_self_signed_cert
        else
            obtain_letsencrypt_cert
        fi
    fi
}

configure_nginx_site() {
    if $ENABLE_SSL; then
        configure_nginx_ssl_site
    else
        configure_nginx_http_site
    fi
}

test_and_start_nginx() {
    if nginx -t 2>&1 | tee -a "$LOG_FILE"; then
        success "Nginx配置测试通过"
        start_nginx_service
    else
        error "Nginx配置测试失败，请检查配置"
    fi
}

start_nginx_service() {
    systemctl start nginx
    systemctl enable nginx
    sleep 2
    
    if systemctl is-active --quiet nginx; then
        success "Nginx服务启动成功"
    else
        error "Nginx服务启动失败，请检查日志: journalctl -u nginx -n 20"
    fi
}

configure_nginx_http_site() {
    cat > $NGINX_CONF_DIR/wg-relay.conf << EOF
server {
    listen $NGINX_PORT;
    server_name _;
    
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location ~ /\. {
        deny all;
    }
    
    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_buffering off;
        proxy_buffer_size 4k;
    }
    
    access_log /var/log/nginx/wg-relay-access.log;
    error_log /var/log/nginx/wg-relay-error.log;
}
EOF
}

configure_nginx_ssl_site() {
    create_ssl_params_snippet
    create_nginx_ssl_config
    set_config_permissions
}

create_ssl_params_snippet() {
    cat > /etc/nginx/snippets/ssl-params.conf << 'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_ecdh_curve secp384r1;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
EOF
}

create_nginx_ssl_config() {
    if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
        generate_self_signed_cert
    fi

    cat > $NGINX_CONF_DIR/wg-relay.conf << EOF
# HTTP重定向
server {
    listen $NGINX_PORT;
    server_name $DOMAIN_NAME;
    root /var/www/html;
    
    location /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS服务器
server {
    listen $SSL_PORT ssl;
    server_name $DOMAIN_NAME;
    
    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    
    include /etc/nginx/snippets/ssl-params.conf;
    
    location ~ /\. {
        deny all;
    }
    
    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_buffering off;
        proxy_buffer_size 4k;
    }
    
    access_log /var/log/nginx/wg-relay-ssl-access.log;
    error_log /var/log/nginx/wg-relay-ssl-error.log;
}
EOF
}

set_config_permissions() {
    chmod 644 $NGINX_CONF_DIR/wg-relay.conf
    chmod 644 /etc/nginx/snippets/ssl-params.conf
}

generate_self_signed_cert() {
    info "生成自签名SSL证书..."
    
    [ ! -x "$(command -v openssl)" ] && error "OpenSSL未安装"
    
    mkdir -p $CERT_DIR
    
    openssl genrsa -out $CERT_DIR/privkey.pem 2048 2>/dev/null
    
    cat > /tmp/cert.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = CN
O = WireGuard Relay
CN = $DOMAIN_NAME

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN_NAME
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $PUBLIC_IP
EOF
    
    openssl req -x509 -nodes -days 3650 \
        -key $CERT_DIR/privkey.pem \
        -out $CERT_DIR/fullchain.pem \
        -config /tmp/cert.conf 2>/dev/null
    
    chmod 600 $CERT_DIR/privkey.pem
    chmod 644 $CERT_DIR/fullchain.pem
    
    rm -f /tmp/cert.conf
    success "自签名SSL证书生成完成"
}

obtain_letsencrypt_cert() {
    info "获取Let\'s Encrypt SSL证书..."
    
    [ ! -x "$(command -v certbot)" ] && {
        warn "Certbot未安装，使用自签名证书"
        generate_self_signed_cert
        return
    }
    
    local safe_domain
    safe_domain=$(echo "$DOMAIN_NAME" | tr -cd \'a-zA-Z0-9.-\')
    if [ "$safe_domain" != "$DOMAIN_NAME" ]; then
        warn "域名包含非法字符，已清理: $DOMAIN_NAME -> $safe_domain"
        DOMAIN_NAME="$safe_domain"
    fi
    local safe_email
    safe_email=$(echo "$EMAIL_ADDRESS" | tr -cd 'a-zA-Z0-9.@_+-')
    
    if ss -tlpn 2>/dev/null | grep -q \':80 \'; then
        warn "端口80已被占用，无法使用standalone模式，尝试使用webroot模式"
        local webroot_path="/var/www/html"
        mkdir -p "$webroot_path/.well-known/acme-challenge"
        local certbot_cmd="certbot certonly --webroot -w $webroot_path --non-interactive --agree-tos"
        [ -n "$EMAIL_ADDRESS" ] && \
            certbot_cmd="$certbot_cmd --email $(printf "%s" "$safe_email")" || \
            certbot_cmd="$certbot_cmd --register-unsafely-without-email"
        certbot_cmd="$certbot_cmd -d $DOMAIN_NAME"
    else
        iptables -A INPUT -i $PUBLIC_INTERFACE -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -i $PUBLIC_INTERFACE -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        local certbot_cmd="certbot certonly --standalone --non-interactive --agree-tos"
        [ -n "$EMAIL_ADDRESS" ] && \
            certbot_cmd="$certbot_cmd --email $(printf "%s" "$safe_email")" || \
            certbot_cmd="$certbot_cmd --register-unsafely-without-email"
        certbot_cmd="$certbot_cmd -d $DOMAIN_NAME --preferred-challenges http"
    fi
    
    if $certbot_cmd 2>&1 | tee -a "$LOG_FILE"; then
        if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
            mkdir -p $CERT_DIR
            cp /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem $CERT_DIR/
            cp /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem $CERT_DIR/
            
            chmod 600 $CERT_DIR/privkey.pem
            chmod 644 $CERT_DIR/fullchain.pem
            
            success "Let\'s Encrypt SSL证书获取成功"
            create_cert_renewal_cron
        fi
    else
        warn "Let\'s Encrypt证书获取失败，使用自签名证书"
        generate_self_signed_cert
    fi
    
    iptables -D INPUT -i $PUBLIC_INTERFACE -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i $PUBLIC_INTERFACE -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    
    log "SSL证书配置完成"
}

create_cert_renewal_cron() {
    info "创建SSL证书自动续期任务..."
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --nginx --quiet && systemctl reload nginx") | crontab -
    success "SSL证书自动续期任务已创建"
}

setup_nginx_and_ssl() {
    configure_nginx_ssl
}

disable_nginx_proxy() {
    info "禁用 Nginx 代理配置..."
    rm -f "$NGINX_CONF_DIR/wg-relay.conf"
    systemctl reload nginx || true
}
