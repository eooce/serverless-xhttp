<div align="center">

# VLESS-XHTTP Proxy Server

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
[![GitHub stars](https://img.shields.io/github/stars/eooce/serverless-xhttp?style=social)](https://github.com/eooce/serverless-xhttp)
[![GitHub forks](https://img.shields.io/github/forks/eooce/serverless-xhttp?style=social)](https://github.com/eooce/serverless-xhttp)
[![GitHub issues](https://img.shields.io/github/issues/eooce/serverless-xhttp)](https://github.com/eooce/serverless-xhttp/issues)
[![GitHub license](https://img.shields.io/github/license/eooce/serverless-xhttp)](https://github.com/eooce/serverless-xhttp/blob/main/LICENSE)


一个高性能的VLESS-XHTTP代理服务器，基于 Python asyncio 实现，单文件、零 Web 框架依赖，支持主流客户端

</div>

## ✨ 特性

- 🚀 **高性能**：优化的数据包处理和内存管理
- 🔄 **全兼容**：支持V2rayN、V2rayNG、Shadowrocket等所有主流客户端
- 🌐 **智能DNS**：使用1.1.1.1和8.8.8.8进行域名解析
- 📊 **性能监控**：实时内存使用和传输统计
- 🛡️ **内存安全**：自动清理和垃圾回收，长期运行稳定
- ⚡ **批处理**：智能数据包批处理，提升传输效率
- 🔧 **可配置**：丰富的环境变量配置选项
- 📊 **哪吒v0/v1**：支持哪吒v0和v1

## 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `UUID` | `a2056d0d-c98e-4aeb-9aab-37f64edd5710` | UUID |
| `NEZHA_SERVER` |  | 哪吒面板地址 v0: 域名 v1: 域名:端口 |
| `NEZHA_KEY` |     | 哪吒密钥 |
| `AUTO_ACCESS` | `false` | 自动保活开关（需配合 `DOMAIN`） |
| `SUB_PATH` | `sub` | 订阅路径 |
| `DOMAIN` |   | 服务器域名或IP，设置后订阅节点使用 TLS:443 |
| `NAME` |     | 节点名称 |
| `PORT` | `3000` | HTTP服务端口 |
| `LOG_LEVEL` | `none` | 日志级别 (none/debug/info/warn/error) |
| `MAX_CONNECTIONS` | `1000` | 最大并发连接数 |

> 说明：XHTTP 路径由 UUID 去掉 `-` 后的前 8 位自动生成，不可通过环境变量修改。

### 订阅链接
* HTTP: `http://your-domain.com:${PORT}/${SUB_PATH}`
* HTTPS: `https://your-domain.com/${SUB_PATH}`

### 使用cloudflare workers 或 snippets 反代域名给xhttp节点套cdn加速
```
export default {
    async fetch(request, env) {
        let url = new URL(request.url);
        if (url.pathname.startsWith('/')) {
            var arrStr = [
                'your-domain', // 此处单引号里填写你的节点伪装域名
            ];
            url.protocol = 'https:'
            url.hostname = getRandomArray(arrStr)
            let new_request = new Request(url, request);
            return fetch(new_request);
        }
        return env.ASSETS.fetch(request);
    },
};
function getRandomArray(array) {
  const randomIndex = Math.floor(Math.random() * array.length);
  return array[randomIndex];
}
```

## 快速部署 

### 1：源代码部署

#### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/eooce/serverless-xhttp
cd serverless-xhttp

# 2. 安装依赖（需要 Python 3.9+）
pip install -r requirements.txt

# 3. 配置环境变量（可选）
export UUID=your-uuid-here
export DOMAIN=your-domain.com
export NAME=MyNode
export LOG_LEVEL=none

# 4. 启动服务
python app.py
```

#### 使用 systemd 管理（推荐）

```bash
# 创建服务文件
cat > /etc/systemd/system/xhttp.service << EOF
[Unit]
Description=VLESS-XHTTP Proxy Server
After=network.target

[Service]
WorkingDirectory=/opt/serverless-xhttp
Environment=UUID=your-uuid-here
Environment=DOMAIN=your-domain.com
Environment=NAME=MyNode
Environment=LOG_LEVEL=none
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable --now xhttp

# 查看状态
systemctl status xhttp

# 查看日志
journalctl -u xhttp -f
```

### 2：Docker部署

#### 构建镜像并运行

```bash
# 构建镜像
docker build -t xhttp:latest .

# 完整配置运行
docker run -d \
  --name vless-proxy \
  -p 3000:3000 \
  -e UUID=your-uuid-here \
  -e DOMAIN=your-domain.com \
  -e NAME=MyNode \
  -e NEZHA_SERVER=your-nezha-server.com \
  -e NEZHA_KEY=your-nezha-key \
  --restart=unless-stopped \
  xhttp:latest
```

#### 使用Docker Compose

```yaml
# docker-compose.yml
services:
  xhttp:
    build: .
    image: xhttp:latest
    container_name: xhttp
    ports:
      - "3000:3000"
    environment:
      - NAME=MyNode
      - UUID=your-uuid-here
      - DOMAIN=your-domain.com
      - NEZHA_SERVER=your-nezha-server.com
      - NEZHA_KEY=your-nezha-key
    restart: unless-stopped
```

```bash
# 构建并启动服务
docker compose up -d --build

# 查看日志
docker compose logs -f

# 停止服务
docker compose down
```

---

### 温馨提示

* 如果使用的是IP:端口或域名:端口形式访问首页，请关闭节点的tls，并将节点端口改为运行的端口。
* 如果需要使用CDN功能，将IP解析到cloudflared，并设置端口回源，然后将节点的host和sni改为解析的域名。
* 请尽量确保在生产环境中使用HTTPS和有效的TLS证书。

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

---
## 如果此项目对你有帮助，请给一颗star

[![Star History Chart](https://api.star-history.com/svg?repos=eooce/serverless-xhttp&type=Date)](https://star-history.com/#eooce/serverless-xhttp&Date)
