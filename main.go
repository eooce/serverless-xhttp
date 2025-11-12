package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	UUID         string
	XPath        string
	SubPath      string
	Domain       string
	Name         string
	Port         string
	LogLevel     string
	ChunkSize    int
	NezhaServer  string
	NezhaPort    string
	NezhaKey     string
	AutoAccess   bool
}

type VlessSession struct {
	UUID           string
	Remote         net.Conn
	ResponseHeader []byte
	mu             sync.Mutex
}

type CloudflareSpeedMeta struct {
	Country        string `json:"country"`
	AsOrganization string `json:"asOrganization"`
}

var (
	config       *Config
	sessions     = make(map[string]*VlessSession)
	sessionsMu   sync.RWMutex
	logger       *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "[Server] ", log.LstdFlags)
}

// load config
func loadConfig() *Config {
	uuid := getEnv("UUID", "a2056d0d-c98e-4aeb-9aab-37f64edd5710")  // UUID,哪吒v1依赖UUID
	nezhaServer := getEnv("NEZHA_SERVER", "")    // 哪吒v1形式：nezha.xxx.com:8008  哪吒v0形式：nezha.xxx.com
	nezhaPort := getEnv("NEZHA_PORT", "")        // 哪吒v1请留空,哪吒v0的agent端口
	nezhaKey := getEnv("NEZHA_KEY", "")          // 哪吒v1的NZ_CLIENT_SECRET或哪吒v0的agent密钥
	subPath := getEnv("SUB_PATH", "sub")         // 节点订阅token
	name := getEnv("NAME", "Xhttp")              // 节点名称
	port := getEnv("PORT", "3000")               // 监听端口
	domain := getEnv("DOMAIN", "")               // 服务域名

	xpath := getEnv("XPATH", uuid[:8])
	autoAccess := false
	if getEnv("AUTO_ACCESS", "false") == "true" {  // 是否开启自动保活,true开启,false关闭,默认关闭
		autoAccess = true
	}
	
	return &Config{
		UUID:        uuid,
		XPath:       xpath,
		NezhaServer: nezhaServer,
		NezhaPort:   nezhaPort,
		NezhaKey:    nezhaKey,
		SubPath:     subPath,
		Domain:      domain,
		Name:        name,
		Port:        port,
		ChunkSize:   32768,
		AutoAccess:  autoAccess,
		LogLevel:    getEnv("LOG_LEVEL", "none"), // 日志等级 none, info, debug, warn, error
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Log function
func logf(level, format string, args ...interface{}) {
	levels := map[string]int{"none": -1, "debug": 0, "info": 1, "warn": 2, "error": 3}
	
	configLevel := levels[config.LogLevel]
	messageLevel := levels[level]
	
	// if logevl is none，disable log
	if configLevel == -1 {
		return
	}
	
	if messageLevel >= configLevel {
		msg := fmt.Sprintf(format, args...)
		
		if strings.Contains(msg, "Failed to connect") {
			if level == "error" {
				level = "warn"
			}
		}
		
		if strings.Contains(msg, "Processing POST data") ||
		   strings.Contains(msg, "Client read error: read tcp") ||
		   strings.Contains(msg, "Client write error: write tcp") ||
		   strings.Contains(msg, "Remote read error") ||
		   strings.Contains(msg, "Remote write error") ||
		   strings.Contains(msg, "connection reset by peer") ||
		   strings.Contains(msg, "use of closed network connection") {
			return 
		}
		
		logger.Printf("[%s] %s", strings.ToUpper(level), msg)
	}
}

// Analy UUID
func parseUUID(uuidStr string) ([16]byte, error) {
	var uuid [16]byte
	uuidStr = strings.ReplaceAll(uuidStr, "-", "")
	if len(uuidStr) != 32 {
		return uuid, fmt.Errorf("invalid UUID length")
	}
	
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(uuidStr[i*2:i*2+2], 16, 8)
		if err != nil {
			return uuid, err
		}
		uuid[i] = byte(b)
	}
	return uuid, nil
}

// Analy VLS Header
func parseSimpleVlessHeader(data []byte) (string, uint16, []byte, error) {
	if len(data) < 18 {
		return "", 0, nil, fmt.Errorf("data too short")
	}
	
	// Verify UUID
	configUUID, _ := parseUUID(config.UUID)
	receivedUUID := data[1:17]
	
	for i := 0; i < 16; i++ {
		if receivedUUID[i] != configUUID[i] {
			return "", 0, nil, fmt.Errorf("UUID mismatch")
		}
	}
	
	pbLen := data[17]
	offset := 18 + int(pbLen)
	
	if len(data) < offset+4 {
		return "", 0, nil, fmt.Errorf("insufficient data for command/port/atype")
	}
	
	cmd := data[offset]
	if cmd != 1 {
		return "", 0, nil, fmt.Errorf("unsupported command: %d", cmd)
	}
	
	port := binary.BigEndian.Uint16(data[offset+1 : offset+3])
	atype := data[offset+3]
	offset += 4
	
	var hostname string
	switch atype {
	case 1: // IPv4
		if len(data) < offset+4 {
			return "", 0, nil, fmt.Errorf("insufficient data for IPv4")
		}
		hostname = fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
		offset += 4
	case 2: // domain
		if len(data) < offset+1 {
			return "", 0, nil, fmt.Errorf("insufficient data for domain length")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen {
			return "", 0, nil, fmt.Errorf("insufficient data for domain")
		}
		hostname = string(data[offset : offset+domainLen])
		offset += domainLen
	case 3: // IPv6
		if len(data) < offset+16 {
			return "", 0, nil, fmt.Errorf("insufficient data for IPv6")
		}

		hostname = "::1"
		offset += 16
	default:
		return "", 0, nil, fmt.Errorf("unsupported address type: %d", atype)
	}
	
	remaining := data[offset:]
	return hostname, port, remaining, nil
}

// Handling VLS Connections - Using Hijack
func handleVlessConnection(w http.ResponseWriter, r *http.Request, uuid string) {

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	
	conn, _, err := hijacker.Hijack()
	if err != nil {
		logf("error", "Failed to hijack connection: %v", err)
		return
	}
	defer conn.Close()
	
	logf("info", "Hijacked connection for session: %s", uuid)
	
	// send HTTP 
	httpResp := "HTTP/1.1 200 OK\r\n"
	httpResp += "Content-Type: application/octet-stream\r\n"
	httpResp += "Connection: close\r\n"
	httpResp += "\r\n"
	
	if _, err := conn.Write([]byte(httpResp)); err != nil {
		logf("error", "Failed to write HTTP response: %v", err)
		return
	}
	
	sessionsMu.Lock()
	session, exists := sessions[uuid]
	if !exists {
		session = &VlessSession{UUID: uuid}
		sessions[uuid] = session
		logf("debug", "Created session placeholder for: %s", uuid)
	}
	sessionsMu.Unlock()
	
	const maxWaitTime = 30 * time.Second 
	const checkInterval = 50 * time.Millisecond
	maxChecks := int(maxWaitTime / checkInterval)
	
	for i := 0; i < maxChecks; i++ {
		session.mu.Lock()
		if session.Remote != nil && session.ResponseHeader != nil {
			session.mu.Unlock()
			logf("debug", "Session initialized after %v for: %s", time.Duration(i)*checkInterval, uuid)
			break
		}
		session.mu.Unlock()
		
		if i > 0 && i%(int(5*time.Second/checkInterval)) == 0 {
			logf("debug", "Still waiting for session initialization: %s (%.1fs)", uuid, float64(i)*checkInterval.Seconds())
		}
		
		time.Sleep(checkInterval)
	}
	
	session.mu.Lock()
	if session.Remote == nil {
		session.mu.Unlock()
		logf("error", "Session not initialized within timeout: %s", uuid)
		return
	}
	
	if _, err := conn.Write(session.ResponseHeader); err != nil {
		session.mu.Unlock()
		logf("error", "Failed to write VLS response: %v", err)
		return
	}
	
	remote := session.Remote
	session.mu.Unlock()
	
	logf("info", "Starting data relay for session: %s", uuid)
	
	// Enable bidirectional data forwarding
	done := make(chan bool, 2)
	
	// From remote to client
	go func() {
		defer func() { done <- true }()
		buffer := make([]byte, config.ChunkSize)
		for {
			n, err := remote.Read(buffer)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "connection reset") {
					logf("warn", "Remote connection error for %s", uuid)
				}
				break
			}
			if n > 0 {
				if _, err := conn.Write(buffer[:n]); err != nil {
					if !strings.Contains(err.Error(), "connection reset") && !strings.Contains(err.Error(), "closed network connection") {
						logf("warn", "Client write error for %s", uuid)
					}
					break
				}
			}
		}
	}()
	
	// From the client to the remote
	go func() {
		defer func() { done <- true }()
		buffer := make([]byte, config.ChunkSize)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "connection reset") {
					logf("warn", "Client connection error for %s", uuid)
				}
				break
			}
			if n > 0 {
				if _, err := remote.Write(buffer[:n]); err != nil {
					if !strings.Contains(err.Error(), "connection reset") && !strings.Contains(err.Error(), "closed network connection") {
						logf("warn", "Remote write error for %s", uuid)
					}
					break
				}
			}
		}
	}()
	
	<-done
	logf("debug", "Session completed: %s", uuid)
	
	sessionsMu.Lock()
	delete(sessions, uuid)
	sessionsMu.Unlock()
}

// slove post data 
func handleVlessPost(w http.ResponseWriter, r *http.Request, uuid string, seq int) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logf("error", "Failed to read POST body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	
	if seq == 0 {
		logf("debug", "Initializing session: %s", uuid)
	}
	
	sessionsMu.Lock()
	session, exists := sessions[uuid]
	if !exists {
		session = &VlessSession{UUID: uuid}
		sessions[uuid] = session
	}
	sessionsMu.Unlock()
	
	if seq == 0 {
		hostname, port, remaining, err := parseSimpleVlessHeader(body)
		if err != nil {
			logf("error", "Failed to parse VLS header: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		
		logf("info", "VLS connection to %s:%d", hostname, port)
		
		if config.LogLevel == "debug" {
			go diagnoseConnection(hostname, port)
		}
		
		address := fmt.Sprintf("%s:%d", hostname, port)
		var remote net.Conn
		var connErr error
			
		for i := 0; i < 3; i++ {
			remote, connErr = net.DialTimeout("tcp", address, 15*time.Second)
			if connErr == nil {
				break
			}
			if i < 2 {
				logf("warn", "Connection attempt %d failed for %s: %v, retrying...", i+1, address, connErr)
				time.Sleep(1 * time.Second)
			}
		}
			
		if connErr != nil {
			logf("error", "Failed to connect to %s after 3 attempts: %v", address, connErr)
			http.Error(w, "Connection Failed", http.StatusBadGateway)
			return
		}
			
		logf("info", "Successfully connected to %s", address)
		
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
		}
		
		session.mu.Lock()
		session.Remote = remote
		session.ResponseHeader = []byte{0x00, 0x00} 
		session.mu.Unlock()
		
		if len(remaining) > 0 {
			if _, err := remote.Write(remaining); err != nil {
				logf("error", "Failed to write initial data: %v", err)
			}
		}
		
		logf("info", "VLS session initialized: %s", uuid)
	} else {
		session.mu.Lock()
		if session.Remote != nil {
			_, err := session.Remote.Write(body)
			session.mu.Unlock()
			if err != nil {
				logf("error", "Failed to write data to remote: %v", err)
				http.Error(w, "Write Failed", http.StatusBadGateway)
				return
			}
		} else {
			session.mu.Unlock()
			logf("warn", "Received data for uninitialized session: %s", uuid)
		}
	}
	
	w.WriteHeader(http.StatusOK)
}

// get ISP info from Cloudflare
func getISPInfo() string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Get("https://speed.cloudflare.com/meta")
	if err != nil {
		logf("warn", "Failed to get ISP info from Cloudflare: %v", err)
		return "Unknown_ISP"
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logf("warn", "Failed to read ISP response: %v", err)
		return "Unknown_ISP"
	}
	
	var meta CloudflareSpeedMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		logf("warn", "Failed to parse ISP response: %v", err)
		return "Unknown_ISP"
	}
	
	country := strings.ReplaceAll(meta.Country, " ", "")
	asOrg := strings.ReplaceAll(meta.AsOrganization, " ", "_")
	asOrg = strings.ReplaceAll(asOrg, "(", "")
	asOrg = strings.ReplaceAll(asOrg, ")", "")
	
	isp := fmt.Sprintf("%s_%s", country, asOrg)
	logf("debug", "Got ISP info: %s (Country: %s, ASOrganization: %s)", isp, meta.Country, meta.AsOrganization)
	
	return isp
}

// http server
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// root path
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Hello, World\n")
		return
	}
	
	// sub route
	if r.URL.Path == "/"+config.SubPath {
		ip := config.Domain
		if ip == "" {
			ip = getServerIP()
		}
		
		if net.ParseIP(ip) == nil && !strings.Contains(ip, ".") {
			ip = "localhost"
			logf("warn", "Invalid IP format detected, using localhost")
		}
		
		if strings.Contains(ip, "<") || strings.Contains(ip, ">") {
			ip = "localhost"
			logf("warn", "HTML content detected in IP, using localhost")
		}
		
		isp := getISPInfo()
		nodeName := fmt.Sprintf("%s_%s", config.Name, isp)
		
		vlessURL := fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&type=xhttp&host=%s&sni=%s&alpn=h2%2Chttp%2F1.1&fp=chrome&path=%%2F%s&mode=packet-up#%s",
			config.UUID, ip, ip, ip, config.XPath, nodeName)
		
		logf("debug", "Generated subscription URL: %s", vlessURL)
		
		base64Content := base64.StdEncoding.EncodeToString([]byte(vlessURL))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprintf(w, "%s\n", base64Content)
		return
	}
	
	if !strings.Contains(r.URL.Path, config.XPath) {
		http.NotFound(w, r)
		return
	}
	
	// path prefix
	pathPrefix := fmt.Sprintf("/%s/", config.XPath)
	if !strings.HasPrefix(r.URL.Path, pathPrefix) {
		http.NotFound(w, r)
		return
	}
	
	remaining := strings.TrimPrefix(r.URL.Path, pathPrefix)
	parts := strings.Split(remaining, "/")
	
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	
	uuid := parts[0]
	
	if r.Method == "GET" && len(parts) == 1 {
		handleVlessConnection(w, r, uuid)
		return
	}
	
	if r.Method == "POST" && len(parts) == 2 {
		seq, err := strconv.Atoi(parts[1])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		handleVlessPost(w, r, uuid, seq)
		return
	}
	
	http.NotFound(w, r)
}

// network diagnose
func diagnoseConnection(hostname string, port uint16) {
	address := fmt.Sprintf("%s:%d", hostname, port)
	
	ips, err := net.LookupIP(hostname)
	if err != nil {
		logf("warn", "DNS resolution failed for %s: %v", hostname, err)
		return
	}
	
	logf("debug", "DNS resolved %s to %v", hostname, ips)
	
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		logf("warn", "Quick connection test failed for %s: %v", address, err)
		return
	}
	conn.Close()
	logf("debug", "Quick connection test successful for %s", address)
}

// get server IP
func getServerIP() string {
	services := []string{
		"https://ip.sb",
		"https://ipinfo.io/ip",
		"https://api.ipify.org",
		"https://ifconfig.me",

	}
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if err != nil {
			continue
		}
		
		ip := strings.TrimSpace(string(body))
		
		if net.ParseIP(ip) != nil {
			logf("debug", "Got IP from %s: %s", service, ip)
			return ip
		}
	}
	
	// if all services fail, try to get local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		logf("debug", "Using local IP: %s", localAddr.IP)
		return localAddr.IP.String()
	}
	
	logf("warn", "Failed to get server IP, using localhost")
	return "localhost"
}

// get nz download url
func getNezhaDownloadURL() (string, string) {
	if config.NezhaServer == "" || config.NezhaKey == "" {
		return "", ""
	}
	
	arch := runtime.GOARCH
	var version string
	
	if config.NezhaServer != "" && config.NezhaPort != "" && config.NezhaKey != "" {
		version = "agent"
	} else if config.NezhaServer != "" && config.NezhaKey != "" && strings.Contains(config.NezhaServer, ":") {
		version = "v1"
	} else {
		return "", ""
	}
	
	var url string
	if arch == "arm" || arch == "arm64" {
		url = fmt.Sprintf("https://arm64.ssss.nyc.mn/%s", version)
	} else {
		url = fmt.Sprintf("https://amd64.ssss.nyc.mn/%s", version)
	}
	
	return url, version
}

// download nz
func downloadNezhaAgent() (string, error) {
	url, version := getNezhaDownloadURL()
	if url == "" {
		return "", nil 
	}
	
	logf("info", "Downloading Nezha agent from %s", url)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download: %v", err)
	}
	defer resp.Body.Close()
	
	file, err := os.Create("npm")
	if err != nil {
		return "", fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()
	
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to save file: %v", err)
	}
	
	err = os.Chmod("npm", 0755)
	if err != nil {
		return "", fmt.Errorf("failed to set permissions: %v", err)
	}
	
	fmt.Println("nezha downloaded successfully")
	return version, nil
}

// create nz config
func createNezhaConfig(version string) error {
	if version == "agent" {
		return nil
	}
	
	if version == "v1" {
		server := config.NezhaServer
		var port string
		
		if strings.Contains(server, ":") {
			parts := strings.Split(server, ":")
			if len(parts) == 2 {
				server = parts[0]
				port = parts[1] 
			} else {
				return fmt.Errorf("invalid NEZHA_SERVER format: %s", config.NezhaServer)
			}
		} else {
			return fmt.Errorf("No port found in NEZHA_SERVER")
		}
		
		tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
		tls := "false"
		for _, tlsPort := range tlsPorts {
			if port == tlsPort {
				tls = "true"
				break
			}
		}
		
		serverAddr := fmt.Sprintf("%s:%s", server, port)
		
		configContent := fmt.Sprintf(`client_secret: %s
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: %s
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: %s
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: %s`,
			config.NezhaKey, serverAddr, tls, config.UUID)
		
		err := os.WriteFile("config.yaml", []byte(configContent), 0644)
		if err != nil {
			return fmt.Errorf("failed to create config file: %v", err)
		}
		
		logf("info", "Nezha v1 config file created for %s with TLS: %s", serverAddr, tls)
	}
	
	return nil
}

// run nz
func runNezhaAgent(version string) error {
	var cmd *exec.Cmd
	
	if version == "agent" {
		tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
		tlsFlag := ""
		for _, port := range tlsPorts {
			if config.NezhaPort == port {
				tlsFlag = "--tls"
				break
			}
		}
		
		server := fmt.Sprintf("%s:%s", config.NezhaServer, config.NezhaPort)
		args := []string{"-s", server, "-p", config.NezhaKey}
		if tlsFlag != "" {
			args = append(args, tlsFlag)
		}
		
		cmd = exec.Command("./npm", args...)
	} else if version == "v1" {
		cmd = exec.Command("./npm", "-c", "config.yaml")
	} else {
		return fmt.Errorf("unknown version: %s", version)
	}
	
	cmd.Stdout = nil
	cmd.Stderr = nil
	
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start nezha agent: %v", err)
	}
	
	fmt.Println("nezha is running")
	return nil
}

// download nz
func startNezhaAgent() {
	if config.NezhaServer == "" || config.NezhaKey == "" {
		logf("info", "Nezha agent doesn't enable")
		return
	}
	
	go func() {
		version, err := downloadNezhaAgent()
		if err != nil {
			logf("error", "Failed to download Nezha agent: %v", err)
			return
		}
		
		if version == "" {
			logf("info", "Nezha agent doesn't need to download")
			return
		}
		
		err = createNezhaConfig(version)
		if err != nil {
			logf("error", "Failed to create Nezha config: %v", err)
			return
		}
		
		time.Sleep(3 * time.Second)
		
		err = runNezhaAgent(version)
		if err != nil {
			logf("error", "Failed to run Nezha agent: %v", err)
			return
		}
	}()
}

// add auto access task
func addAccessTask() {
	if !config.AutoAccess {
		return
	}
	
	if config.Domain == "" {
		logf("warn", "AUTO_ACCESS enabled but DOMAIN is empty")
		return
	}
	
	fullURL := fmt.Sprintf("https://%s", config.Domain)
	command := fmt.Sprintf(`curl -X POST "https://oooo.serv00.net/add-url" -H "Content-Type: application/json" -d '{"url": "%s"}'`, fullURL)
	
	cmd := exec.Command("sh", "-c", command)
	err := cmd.Run()
	if err != nil {
		logf("error", "Error sending access task request: %v", err)
		return
	}
	
	fmt.Printf("Access task add successfully")
}

func main() {
	config = loadConfig()
	
	startNezhaAgent()

	addAccessTask()
	
	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	fmt.Printf("Server is running on port %s\n", config.Port)
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
		logf("error", "Server error: %v", err)
	}
}
