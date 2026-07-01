import { currentLang } from "../i18n";

export function processMeaning(process: string): string {
  const name = process.toLowerCase();
  const zh: [RegExp, string][] = [
    [/rapportd/, "Apple 设备互通服务，通常用于接力、通用剪贴板、附近设备连接等本地通信"],
    [/controlcenter/, "macOS 控制中心/隔空播放相关服务，常见于 5000、7000 等本地共享端口"],
    [/mdnsresponder/, "Bonjour/mDNS 服务发现进程，用于局域网内发现打印机、AirPlay、共享服务等"],
    [/com\.docker\.backend|docker/, "Docker Desktop 后端，通常是容器或本机映射服务在监听端口"],
    [/node/, "Node.js 开发服务或前端 dev server，常见于 5173、3000、8080 等端口"],
    [/launchd/, "macOS 系统服务管理器，通常代表系统级网络服务由 launchd 托管"],
    [/cupsd/, "打印服务进程，通常用于本机或局域网打印服务"],
    [/sshd/, "SSH 远程登录服务"],
    [/nginx/, "Nginx Web/反向代理服务"],
    [/java/, "Java 应用服务，可能是业务应用、中间件或开发服务"],
    [/mysqld|mysql/, "MySQL 数据库服务"],
    [/postgres|postgresql/, "PostgreSQL 数据库服务"],
    [/redis/, "Redis 缓存/键值数据库服务"],
    [/python/, "Python 应用或脚本启动的网络服务"],
    [/configd/, "macOS 网络配置守护进程，负责网络状态、DHCP、DNS 等配置"],
    [/airportd/, "macOS Wi-Fi 管理守护进程"],
    [/replicatord/, "Apple 数据同步/复制相关后台服务"],
  ];
  const en: [RegExp, string][] = [
    [/rapportd/, "Apple device continuity service, commonly used for Handoff, Universal Clipboard, and nearby-device communication"],
    [/controlcenter/, "macOS Control Center/AirPlay-related service, often seen on local sharing ports such as 5000 or 7000"],
    [/mdnsresponder/, "Bonjour/mDNS discovery service for printers, AirPlay, and LAN service discovery"],
    [/com\.docker\.backend|docker/, "Docker Desktop backend, usually a container or local port-mapped service"],
    [/node/, "Node.js app or frontend dev server, commonly seen on ports such as 5173, 3000, or 8080"],
    [/launchd/, "macOS service manager, usually indicating a system service managed by launchd"],
    [/cupsd/, "printing service process"],
    [/sshd/, "SSH remote login service"],
    [/nginx/, "Nginx web or reverse-proxy service"],
    [/java/, "Java application service, middleware, or development service"],
    [/mysqld|mysql/, "MySQL database service"],
    [/postgres|postgresql/, "PostgreSQL database service"],
    [/redis/, "Redis cache/key-value database service"],
    [/python/, "network service started by a Python application or script"],
    [/configd/, "macOS network configuration daemon for network state, DHCP, and DNS settings"],
    [/airportd/, "macOS Wi-Fi management daemon"],
    [/replicatord/, "Apple data sync/replication background service"],
  ];
  const table = currentLang === "en" ? en : zh;
  return table.find(([re]) => re.test(name))?.[1] || "";
}
