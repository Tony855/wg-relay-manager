#!/bin/bash

# ===========================================
# 依赖安装函数库
# ===========================================

# 自动检测 lib 目录位置
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/utils.sh"

# ============================ 依赖安装函数 ============================

install_dependencies() {
    info "正在检测和安装系统依赖..."
    local packages=("curl" "wget" "git" "python3" "python3-pip" "nginx" "iptables" "flock" "jq" "net-tools" "openssl")
    local missing_packages=()

    case $OS in
        ubuntu|debian)
            apt_update_cmd="apt update -y"
            apt_install_cmd="apt install -y"
            ;; 
        centos|rhel|fedora|almalinux|rocky)
            yum_install_cmd="yum install -y"
            ;; 
        *)
            error "不支持的操作系统类型: $OS"
            ;;
    esac

    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            missing_packages+=("$pkg")
        fi
    done

    if [ ${#missing_packages[@]} -gt 0 ]; then
        warn "以下系统依赖未安装：${missing_packages[*]}"
        info "尝试安装系统依赖..."
        case $OS in
            ubuntu|debian)
                $apt_update_cmd
                $apt_install_cmd "${missing_packages[@]}"
                ;; 
            centos|rhel|fedora|almalinux|rocky)
                $yum_install_cmd "${missing_packages[@]}"
                ;; 
        esac

        for pkg in "${packages[@]}"; do
            if ! command -v "$pkg" >/dev/null 2>&1; then
                error "系统依赖 $pkg 安装失败，请手动安装"
            fi
        done
    fi
    success "系统依赖安装完成"

    info "正在检测和安装Python依赖..."
    local python_packages=("flask" "werkzeug" "flask_httpauth" "psutil" "requests")
    local missing_python_packages=()
    local pip_break=""

    if python3 -c "import sys; assert sys.version_info.major >= 3 and sys.version_info.minor >= 6" 2>/dev/null; then
        log "Python 3.6+ 已安装"
    else
        error "需要 Python 3.6 或更高版本"
    fi

    if python3 -m pip --version | grep -q "--break-system-packages"; then
        pip_break="--break-system-packages"
    fi
    
    for package in "${python_packages[@]}"; do
        if ! python3 -c "import $package" 2>/dev/null; then
            missing_python_packages+=($package)
        fi
    done

    if [ ${#missing_python_packages[@]} -gt 0 ]; then
        warn "以下Python依赖未安装：${missing_python_packages[*]}"
        warn "尝试使用系统包管理器或 pip 安装..."
        
        for pkg in "${missing_python_packages[@]}"; do
            if [ "$pkg" = "werkzeug" ]; then
                case $OS in
                    ubuntu|debian)
                        apt-get install -y python3-werkzeug || \
                        pip3 install werkzeug $pip_break
                        ;;
                    *)
                        pip3 install werkzeug $pip_break
                        ;;
                esac
            else
                pip_name="$pkg"
                [ "$pkg" = "flask_httpauth" ] && pip_name="Flask-HTTPAuth"
                [ "$pkg" = "psutil" ] && pip_name="psutil"
                [ "$pkg" = "requests" ] && pip_name="requests"
                [ "$pkg" = "flask" ] && pip_name="Flask"
                
                pip3 install $pip_name $pip_break
            fi
        done
        
        for package in "${python_packages[@]}"; do
            if ! python3 -c "import $package" 2>/dev/null; then
                error "$package 安装失败，请手动安装：pip3 install $package $pip_break"
            fi
        done
    fi
    
    log "Python依赖安装完成"
}
