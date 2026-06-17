# 安装流程

本文档用于说明如何在一台全新的 Linux 服务器上安装 `wg-relay-manager`，并完成首次启动与基本验证。

## 适用环境

- 建议系统：`Ubuntu`、`Debian`、`CentOS`、`Rocky Linux`、`AlmaLinux`、`Fedora`
- 需要 `root` 权限或可使用 `sudo`
- 服务器需要可联网，用于安装系统依赖和 Python 依赖
- 如果要启用 HTTPS，需提前准备已经解析到服务器公网 IP 的域名

## 安装前准备

建议先完成以下检查：

1. 更新系统软件包索引
2. 确认服务器有公网网卡
3. 确认 `80`、`443` 以及你的转发业务端口未被占用
4. 如果服务器启用了 `ufw` 或 `firewalld`，请确认不会覆盖脚本生成的 `iptables` 规则

可以先执行：

```bash
sudo apt update
sudo apt install -y git curl
```

如果你使用的是 `CentOS` / `Rocky Linux` / `AlmaLinux` / `Fedora`，可改为：

```bash
sudo yum install -y git curl
```

## 获取源码

执行以下命令拉取仓库：

```bash
git clone https://github.com/Tony855/wg-relay-manager.git
cd wg-relay-manager
```

## 开始安装

主入口脚本是 `main.sh`，需要使用 `root` 权限运行：

```bash
sudo bash main.sh
```

启动后会进入菜单界面。首次安装建议按下面顺序操作。

## 首次安装步骤

### 1. 安装运行环境

在主菜单中选择：

```text
1. 安装/更新 WireGuard 中继环境
```

这一步会自动完成以下工作：

- 安装系统依赖，如 `python3`、`python3-pip`、`nginx`、`iptables`、`jq`
- 安装 Python 依赖，如 `Flask`、`Werkzeug`、`psutil`
- 配置内核转发参数
- 初始化并保存 `iptables` 规则链

### 2. 配置系统参数

回到主菜单后，选择：

```text
4. 配置系统参数
```

建议至少设置这些内容：

- 中继名称
- Web 管理员用户名
- Web 管理员密码
- 公网接口名称，例如 `eth0`、`ens3`

配置会写入：

```text
/etc/wg-relay/config.json
```

### 3. 启动 Web 管理界面

在主菜单中选择：

```text
3. 启动/停止/重启 Web 管理界面
```

然后选择：

```text
1. 启动 Web 管理界面
```

程序会启动 Flask Web 服务，并由 `systemd` 托管。

### 4. 如果需要 HTTPS，再配置 Nginx 和 SSL

仍在 Web 管理菜单中，选择：

```text
4. 重新配置 Nginx 和 SSL
```

适用场景：

- 你已经准备好了域名
- 域名已经解析到服务器公网 IP
- 你希望通过 HTTPS 访问管理后台

如果暂时没有域名，也可以先使用 HTTP 或先只启用本地 Web 服务。

## 安装完成后如何访问

安装完成后，可以按以下方式访问：

- HTTP：`http://服务器IP:80`
- HTTPS：`https://你的域名`
- 如果仅启动了 Web 服务但未完成 Nginx 代理，默认 Flask 端口通常为 `8080`

如果忘记当前配置，可以检查：

```bash
sudo cat /etc/wg-relay/config.json
sudo cat /etc/wg-relay/.credentials
```

## 首次登录后建议做的事

首次进入 Web 管理后台后，建议立即完成以下操作：

1. 修改默认管理员密码
2. 添加第一条转发规则
3. 检查系统状态页中的 CPU、内存、连接数和网卡流量
4. 确认转发端口已经正常监听和放行

## 常用管理命令

安装完成后，常见操作如下：

查看服务状态：

```bash
sudo systemctl status wg-relay-web
sudo systemctl status nginx
```

重启 Web 服务：

```bash
sudo systemctl restart wg-relay-web
```

查看日志：

```bash
sudo tail -n 100 /var/log/wg-relay.log
sudo journalctl -u wg-relay-web -n 100 --no-pager
```

列出规则：

```bash
sudo wg-rule-manager list
```

重新加载规则：

```bash
sudo wg-rule-manager reload
```

查看统计：

```bash
sudo python3 scripts/stats_collector.py
```

## 升级流程

如果你已经安装过旧版本，建议按下面方式更新：

```bash
cd wg-relay-manager
git pull
sudo bash main.sh
```

然后在主菜单中再次执行：

```text
1. 安装/更新 WireGuard 中继环境
```

如有需要，再进入 Web 管理菜单重启 Web 服务或重新配置 Nginx / SSL。

## 卸载流程

如果要移除本项目，运行：

```bash
sudo bash main.sh
```

然后在主菜单中选择：

```text
6. 卸载脚本
```

该操作会停止 Web 服务、删除规则、移除相关配置和安装产物，请谨慎执行。

## 常见问题

### 1. 提示必须使用 root 运行

请改用：

```bash
sudo bash main.sh
```

### 2. Web 页面打不开

请按顺序检查：

```bash
sudo systemctl status wg-relay-web
sudo systemctl status nginx
sudo ss -tlpn | grep -E ':80|:443|:8080'
```

### 3. HTTPS 证书申请失败

通常需要确认：

- 域名已经正确解析
- `80` / `443` 端口可从公网访问
- 服务器没有其他 Web 服务占用这些端口

### 4. 规则添加成功但转发不生效

建议检查：

- 目标 IP 和端口是否可达
- 服务器内核转发是否已开启
- `iptables` 规则是否已生成
- 上游防火墙是否拦截了业务端口

可执行：

```bash
sudo iptables -L -n
sudo iptables -t nat -L -n
```
