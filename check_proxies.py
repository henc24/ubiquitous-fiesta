# -*- coding: utf-8 -*-
"""
Простой чекер прокси — читает all_proxies_merged.txt, проверяет, сохраняет рабочие
"""

import os
import base64
import asyncio
import json
import subprocess
import tempfile
import time
from urllib.parse import urlparse, unquote
from dataclasses import dataclass
import aiohttp
from aiohttp_socks import ProxyConnector

# ============== НАСТРОЙКИ ==============
INPUT_FILE = 'all_proxies_merged.txt'
OUTPUT_FILE = 'working_proxies.txt'

TIMEOUT_TCP = 5           # Таймаут TCP пинга
TIMEOUT_PROXY = 20        # Таймаут проверки через прокси
STARTUP_DELAY = 2         # Время запуска sing-box
MAX_CONCURRENT = 30       # Параллельных проверок
MAX_LATENCY_MS = 3000     # Максимальный пинг (мс)

# Тестовые URL
CONNECTIVITY_URLS = [
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/",
]
IP_CHECK_URL = "https://api.ipify.org"


@dataclass
class CheckResult:
    key: str
    working: bool
    latency_ms: int = 0
    error: str = ""


def decode_base64(data: str) -> str:
    """Декодирует base64"""
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data = data + '=' * padding
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except:
        return ""


def get_key_name(key: str) -> str:
    """Извлекает имя ключа для логов"""
    if '#' in key:
        return unquote(key.split('#')[-1])[:40]
    try:
        parsed = urlparse(key)
        return f"{parsed.hostname}:{parsed.port}"[:40]
    except:
        return key[:40]


def get_host_port(key: str):
    """Извлекает хост и порт из ключа"""
    try:
        if key.startswith('vmess://'):
            data = json.loads(decode_base64(key[8:]))
            return data.get('add'), int(data.get('port', 443))
        else:
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
    except:
        pass
    return None, None


# ============== SING-BOX КОНФИГИ ==============

def parse_vless(uri: str):
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "uuid": parsed.username,
            "flow": params.get('flow', ''),
        }
        
        security = params.get('security', 'none')
        if security == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')}
            }
        elif security == 'reality':
            outbound["tls"] = {
                "enabled": True,
                "server_name": params.get('sni', ''),
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": params.get('fp', 'chrome')},
                "reality": {
                    "enabled": True,
                    "public_key": params.get('pbk', ''),
                    "short_id": params.get('sid', '')
                }
            }
        
        transport_type = params.get('type', 'tcp')
        if transport_type == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": unquote(params.get('path', '/')),
                "headers": {"Host": params.get('host', parsed.hostname)}
            }
        elif transport_type == 'grpc':
            outbound["transport"] = {"type": "grpc", "service_name": params.get('serviceName', '')}
        
        return outbound
    except:
        return None


def parse_vmess(uri: str):
    try:
        data = json.loads(decode_base64(uri[8:]))
        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": data.get('add'),
            "server_port": int(data.get('port', 443)),
            "uuid": data.get('id'),
            "security": data.get('scy', 'auto'),
            "alter_id": int(data.get('aid', 0))
        }
        
        if data.get('tls') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": data.get('sni', data.get('host', '')),
                "insecure": True
            }
        
        net = data.get('net', 'tcp')
        if net == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', '')}
            }
        
        return outbound
    except:
        return None


def parse_ss(uri: str):
    try:
        key_part = uri[5:].split('#')[0]
        
        if '@' in key_part:
            method_pass, host_port = key_part.rsplit('@', 1)
            decoded = decode_base64(method_pass)
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                return None
            host, port = host_port.rsplit(':', 1)
        else:
            decoded = decode_base64(key_part)
            if '@' in decoded:
                method_pass, host_port = decoded.rsplit('@', 1)
                method, password = method_pass.split(':', 1)
                host, port = host_port.rsplit(':', 1)
            else:
                return None
        
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password
        }
    except:
        return None


def parse_trojan(uri: str):
    try:
        parsed = urlparse(uri)
        params = dict(p.split('=', 1) for p in parsed.query.split('&') if '=' in p)
        
        return {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": unquote(parsed.username),
            "tls": {
                "enabled": True,
                "server_name": params.get('sni', parsed.hostname),
                "insecure": True
            }
        }
    except:
        return None


def key_to_config(key: str, socks_port: int):
    """Конвертирует ключ в sing-box конфиг"""
    outbound = None
    
    if key.startswith('vless://'):
        outbound = parse_vless(key)
    elif key.startswith('vmess://'):
        outbound = parse_vmess(key)
    elif key.startswith('ss://'):
        outbound = parse_ss(key)
    elif key.startswith('trojan://'):
        outbound = parse_trojan(key)
    
    if not outbound:
        return None
    
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}]
    }


# ============== ПРОВЕРКИ ==============

async def check_tcp(host: str, port: int):
    """TCP проверка + latency"""
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT_TCP
        )
        latency = int((time.time() - start) * 1000)
        writer.close()
        await writer.wait_closed()
        return True, latency
    except:
        return False, 0


async def check_connectivity(session):
    """Проверка соединения через прокси"""
    for url in CONNECTIVITY_URLS:
        try:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                if resp.status in [200, 204, 301, 302, 403]:
                    return True
        except:
            continue
    return False


async def check_key(key: str, semaphore, counter: list, total: int, my_ip: str) -> CheckResult:
    """Проверка одного ключа"""
    
    async with semaphore:
        counter[0] += 1
        num = counter[0]
        port = 20000 + (num % 5000)
        name = get_key_name(key)
        
        result = CheckResult(key=key, working=False)
        
        # TCP проверка
        host, server_port = get_host_port(key)
        if host and server_port:
            tcp_ok, latency = await check_tcp(host, server_port)
            result.latency_ms = latency
            
            if not tcp_ok:
                print(f"[{num}/{total}] ✗ {name} — TCP недоступен")
                return result
            
            if latency > MAX_LATENCY_MS:
                print(f"[{num}/{total}] ✗ {name} — пинг {latency}ms слишком высокий")
                return result
        
        # Sing-box проверка
        config = key_to_config(key, port)
        if not config:
            print(f"[{num}/{total}] ✗ {name} — не удалось распарсить")
            return result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = f.name
        
        process = None
        try:
            process = subprocess.Popen(
                ['sing-box', 'run', '-c', config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            await asyncio.sleep(STARTUP_DELAY)
            
            if process.poll() is not None:
                print(f"[{num}/{total}] ✗ {name} — sing-box упал")
                return result
            
            proxy_url = f"socks5://127.0.0.1:{port}"
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_PROXY)
            connector = ProxyConnector.from_url(proxy_url)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Проверка соединения
                if not await check_connectivity(session):
                    print(f"[{num}/{total}] ✗ {name} — нет соединения")
                    return result
                
                # Проверка смены IP
                try:
                    async with session.get(IP_CHECK_URL, ssl=False) as resp:
                        if resp.status == 200:
                            exit_ip = (await resp.text()).strip()
                            if exit_ip and exit_ip != my_ip:
                                result.working = True
                                print(f"[{num}/{total}] ✓ {name} — {result.latency_ms}ms — IP: {exit_ip}")
                                return result
                except:
                    pass
                
                # Если IP не проверился, но соединение есть — считаем рабочим
                result.working = True
                print(f"[{num}/{total}] ✓ {name} — {result.latency_ms}ms")
                return result
                
        except Exception as e:
            print(f"[{num}/{total}] ✗ {name} — ошибка: {e}")
            return result
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            try:
                os.unlink(config_path)
            except:
                pass


async def get_my_ip() -> str:
    """Получает текущий IP"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(IP_CHECK_URL) as resp:
                return (await resp.text()).strip()
    except:
        return ""


async def main():
    print("=" * 50)
    print("Proxy Checker")
    print("=" * 50)
    
    # Проверяем sing-box
    try:
        result = subprocess.run(['sing-box', 'version'], capture_output=True, text=True)
        print(f"sing-box: {result.stdout.split()[2] if result.stdout else 'OK'}")
    except FileNotFoundError:
        print("ОШИБКА: sing-box не найден! Установи его.")
        return
    
    # Читаем ключи
    if not os.path.exists(INPUT_FILE):
        print(f"ОШИБКА: файл {INPUT_FILE} не найден!")
        return
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        keys = [line.strip() for line in f if line.strip()]
    
    # Фильтруем только поддерживаемые протоколы
    protocols = ('vless://', 'vmess://', 'ss://', 'trojan://')
    keys = [k for k in keys if k.startswith(protocols)]
    
    print(f"Загружено ключей: {len(keys)}")
    
    if not keys:
        print("Ключи не найдены!")
        return
    
    # Получаем свой IP
    print("\nПолучаю текущий IP...")
    my_ip = await get_my_ip()
    print(f"Мой IP: {my_ip or 'не определён'}")
    
    # Проверяем
    print(f"\n{'=' * 50}")
    print("ПРОВЕРКА")
    print(f"{'=' * 50}\n")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter = [0]
    
    tasks = [check_key(key, semaphore, counter, len(keys), my_ip) for key in keys]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working = [r for r in results if r.working]
    working.sort(key=lambda r: r.latency_ms)  # Сортируем по пингу
    
    # Сохраняем
    print(f"\n{'=' * 50}")
    print("РЕЗУЛЬТАТ")
    print(f"{'=' * 50}")
    print(f"Проверено: {len(results)}")
    print(f"Рабочих: {len(working)}")
    
    if working:
        working_keys = [r.key for r in working]
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(working_keys))
        print(f"\nСохранено в: {OUTPUT_FILE}")
    else:
        print("\nРабочих ключей не найдено!")


if __name__ == '__main__':
    asyncio.run(main())
