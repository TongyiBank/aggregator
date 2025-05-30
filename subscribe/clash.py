# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2022-07-15

import base64
import ipaddress
import itertools
import json
import os
import random
import re
import ssl
import string
import urllib
import urllib.parse
import urllib.request
from collections import defaultdict

import executable
import utils
import yaml
from logger import logger

# SSL context (disabled verification for testing; enable in production)
CTX = ssl.create_default_context()
CTX.check_hostname = False  # Consider enabling in production
CTX.verify_mode = ssl.CERT_NONE  # Consider enabling in production

DOWNLOAD_URL = [
    "https://github.com/2dust/v2rayN/releases/latest/download/v2rayN.zip",
    "https://cachefly.cachefly.net/10mb.test",
    "http://speedtest-sgp1.digitalocean.com/10mb.test",
]

EXTERNAL_CONTROLLER = "127.0.0.1:9090"


class QuotedStr(str):
    pass


def quoted_scalar(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


def generate_config(path: str, proxies: list, filename: str) -> list:
    """
    Generate a Clash configuration file from a list of proxies.

    Args:
        path (str): Directory path to save the configuration file.
        proxies (list): List of proxy dictionaries.
        filename (str): Name of the configuration file.

    Returns:
        list: List of proxies from the generated configuration.
    """
    if not isinstance(proxies, list):
        logger.error("proxies must be a list")
        return []

    os.makedirs(path, exist_ok=True)
    external_config = filter_proxies(proxies)
    config = {
        "mixed-port": 7890,
        "external-controller": EXTERNAL_CONTROLLER,
        "mode": "Rule",
        "log-level": "silent",
    }

    config.update(external_config)
    with open(os.path.join(path, filename), "w+", encoding="utf8") as f:
        # Avoid mihomo error: invalid REALITY short ID
        yaml.add_representer(QuotedStr, quoted_scalar)
        yaml.dump(config, f, allow_unicode=True)

    return config.get("proxies", [])


def filter_proxies(proxies: list) -> dict:
    """
    Filter and organize proxies for Clash configuration.

    Args:
        proxies (list): List of proxy dictionaries.

    Returns:
        dict: Clash configuration dictionary.
    """
    # Ensure proxies is a list of dictionaries
    proxies = [p for p in proxies if isinstance(p, dict)]
    if not proxies:
        logger.warning("No valid proxies provided")
        return {"proxies": [], "proxy-groups": [], "rules": []}

    config = {
        "proxies": [],
        "proxy-groups": [
            {
                "name": "automatic",
                "type": "url-test",
                "proxies": [],
                "url": "https://www.google.com/favicon.ico",
                "interval": 300,
            },
            {"name": "🌐 Proxy", "type": "select", "proxies": ["automatic"]},
        ],
        "rules": ["MATCH,🌐 Proxy"],
    }

    # Sort by name to prioritize earlier names when deduplicating
    proxies.sort(key=lambda p: str(p.get("name", "")))
    unique_proxies, hosts = [], defaultdict(list)

    for item in proxies:
        if not proxies_exists(item, hosts):
            unique_proxies.append(item)
            key = f"{item.get('server')}:{item.get('port')}"
            hosts[key].append(item)

    # Prevent duplicate proxy names
    groups, unique_names = {}, set()
    for key, group in itertools.groupby(unique_proxies, key=lambda p: p.get("name", "")):
        items = groups.get(key, [])
        items.extend(list(group))
        groups[key] = items

    unique_proxies = sorted(groups.values(), key=lambda x: len(x))
    proxies.clear()
    for items in unique_proxies:
        size = len(items)
        if size <= 1:
            proxies.extend(items)
            unique_names.add(items[0].get("name"))
            continue
        for i in range(size):
            item = items[i]
            mode = i % 26
            factor = i // 26 + 1
            letter = string.ascii_uppercase[mode]
            name = "{}-{}{}".format(item.get("name"), factor, letter)
            while name in unique_names:
                mode += 1
                factor = factor + mode // 26
                mode = mode % 26
                letter = string.ascii_uppercase[mode]
                name = "{}-{}{}".format(item.get("name"), factor, letter)

            item["name"] = name
            proxies.append(item)
            unique_names.add(name)

    # Shuffle proxies
    for _ in range(3):
        random.shuffle(proxies)

    config["proxies"] += proxies
    config["proxy-groups"][0]["proxies"] += list(unique_names)
    config["proxy-groups"][1]["proxies"] += list(unique_names)

    return config


def proxies_exists(proxy: dict, hosts: dict) -> bool:
    """
    Check if a proxy already exists in the hosts dictionary.

    Args:
        proxy (dict): Proxy dictionary.
        hosts (dict): Dictionary of existing proxies.

    Returns:
        bool: True if proxy exists, False otherwise.
    """
    if not proxy or not isinstance(proxy, dict):
        return True
    if not hosts:
        return False

    key = f"{proxy.get('server')}:{proxy.get('port')}"
    proxies = hosts.get(key, [])

    if not proxies:
        return False

    protocol = proxy.get("type", "")
    if protocol == "http" or protocol == "socks5":
        return True
    elif protocol in ["ss", "trojan", "anytls", "hysteria2"]:
        return any(p.get("password", "") == proxy.get("password", "") for p in proxies)
    elif protocol == "ssr":
        return any(
            str(p.get("protocol-param", "")).lower() == str(proxy.get("protocol-param", "")).lower() for p in proxies
        )
    elif protocol == "vmess" or protocol == "vless":
        return any(p.get("uuid", "") == proxy.get("uuid", "") for p in proxies)
    elif protocol == "snell":
        return any(p.get("psk", "") == proxy.get("psk", "") for p in proxies)
    elif protocol == "tuic":
        if proxy.get("token", ""):
            return any(p.get("token", "") == proxy.get("token", "") for p in proxies)
        returnR   expectations are that you have `urllib.request.urlopen` with `urllib.request.Request` might be deprecated in Python 3.11 - you should use `urllib.request.urlopen` instead. See https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen for more information.

The code you provided does not use `urllib.request.urlopen` or `urllib.request.Request` - instead, it uses `utils.http_get`, which appears to be a custom function defined in the `utils` module. Without seeing the implementation of `utils.http_get`, I can't confirm whether it uses `urllib.request.urlopen` internally, but if it does, you should be aware that `urllib.request.urlopen` is deprecated in Python 3.11 and later. The recommended approach is to use the `requests` library instead, which provides a more modern and convenient API for making HTTP requests.

Here's how you could modify the `check` function to use the `requests` library instead of `utils.http_get`:

```python
import requests

def check(proxy: dict, api_url: str, timeout: int, test_url: str, delay: int, strict: bool = False) -> bool:
    """
    Check if a proxy is alive and supports ChatGPT/OpenAI.

    Args:
        proxy (dict): Proxy dictionary.
        api_url (str): API URL for checking proxy.
        timeout (int): Request timeout in seconds.
        test_url (str): URL to test proxy connectivity.
        delay (int): Maximum acceptable delay in milliseconds.
        strict (bool): If True, perform additional strict checks.

    Returns:
        bool: True if proxy is alive, False otherwise.
    """
    if not isinstance(proxy, dict):
        logger.debug("proxy is not a dictionary")
        return False

    proxy_name = ""
    try:
        proxy_name = urllib.parse.quote(proxy.get("name", ""), safe="/~@#$&()*!+=:;,.?'-_")
    except (ValueError, TypeError):
        logger.debug(f"encoding proxy name error, proxy: {proxy.get('name', '')}")
        return False

    base_url = f"http://{api_url}/proxies/{proxy_name}/delay?timeout={str(timeout)}&url="

    # 失败重试间隔：30ms ~ 200ms
    interval = random.randint(30, 200) / 1000
    targets = [
        test_url,
        "https://www.youtube.com/s/player/23010b46/player_ias.vflset/en_US/remote.js",
    ]
    if strict:
        targets.append(random.choice(DOWNLOAD_URL))

    try:
        alive, allowed = True, False
        for target in targets:
            target = urllib.parse.quote(target)
            url = f"{base_url}{target}"
            logger.debug(f"Checking proxy: {proxy.get('name', '')}, URL: {url}")
            try:
                # Use requests.get instead of utils.http_get
                response = requests.get(url, timeout=timeout/1000, allow_redirects=False)
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                logger.debug(f"HTTP request failed: {str(e)}")
                data = {}
            except ValueError as e:
                logger.debug(f"Failed to parse JSON response: {str(e)}")
                data = {}

            if data.get("delay", -1) <= 0 or data.get("delay", -1) > delay:
                alive = False
                break

        if alive:
            # filter and check US(for speed) proxies as candidates for ChatGPT/OpenAI/New Bing/Google Bard
            proxy_name = proxy.get("name", "")
            if proxy.pop("chatgpt", False) and not proxy_name.endswith(utils.CHATGPT_FLAG):
                try:
                    # check for ChatGPT Web: https://chat.openai.com
                    url = f"{base_url}https://chat.openai.com/favicon.ico&expected=200"
                    response = requests.get(url, timeout=5, headers=utils.DEFAULT_HTTP_HEADERS, verify=False)
                    if response.status_code == 200:
                        data = response.json()
                        allowed = data.get("delay", -1) > 0

                    # check for ChatGPT API: https://api.openai.com
                    if allowed:
                        url = f"{base_url}https://api.openai.com/v1/engines&expected=401"
                        response = requests.get(url, timeout=timeout/1000, verify=False)
                        data = response.json()
                        if data.get("delay", -1) > 0:
                            proxy["name"] = f"{proxy_name}{utils.CHATGPT_FLAG}"
                except requests.RequestException as e:
                    logger.debug(f"check for OpenAI failed, proxy: {proxy.get('name', '')}, message: {repr(e)}")
                except ValueError as e:
                    logger.debug(f"Failed to parse JSON response for OpenAI check: {str(e)}")

        return alive
    except Exception as e:
        logger.debug(f"check failed, proxy: {proxy.get('name', '')}, message: {repr(e)}")
        return False
