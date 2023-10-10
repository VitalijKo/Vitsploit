import requests
import threading
import html
import re
import os
import argparse
from lxml import etree
from dotenv import dotenv_values
from printer import info, warn, error, fail

config = dotenv_values('.env')

SHODAN_API_KEY = config['SHODAN_API_KEY']
CENSYS_AUTH_ID = config['CENSYS_AUTH_ID']
CENSYS_AUTH_SECRET = config['CENSYS_AUTH_SECRET']
ZOOMEYE_API_KEY = config['ZOOMEYE_API_KEY']
LEAKIX_API_KEY = config['LEAKIX_API_KEY']


class ShodanAPI:
    def name(self):
        return 'Shodan'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json'
        }

        payload = {
            'key': SHODAN_API_KEY
        }

        r = requests.get(
            f'https://api.shodan.io/shodan/host/{host}',
            headers=headers,
            params=payload
        )

        if r.status_code != 200:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['data']:
            result.append({
                    'port': svc['port'],
                    'service': svc['_shodan']['module'],
                    'transport': svc['transport'],
                    'banner': svc['data'],
                    'product': svc.get('product', None),
                    'version': svc.get('version', None),
                    'cpe': svc.get('cpe23', None),
                    '_source': svc
            })

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class CensysAPI:
    @property
    def name(self):
        return 'Censys'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json'
        }

        r = requests.get(
            f'https://search.censys.io/api/v2/hosts/{host}',
            headers=headers,
            auth=(CENSYS_AUTH_ID, CENSYS_AUTH_SECRET)
        )

        if r.status_code != 200:
            error('Failed to get {bred}Censys{rst}/{byellow}' + host + '{rst}: status code is {bred}' + str(r.status_code) + '{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data.get('result')

    def enum(self, data):
        result = []

        for svc in data['services']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service_name'].lower(),
                    'transport': svc['transport_protocol'].lower(),
                    'banner': svc['banner'],
                    'product': svc.get('software', [{}])[0].get('product', None),
                    'version': svc.get('software', [{}])[0].get('version', None),
                    'cpe': svc.get('software', [{}])[0].get(
                        'uniform_resource_identifier', None
                    ),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ZoomEyeAPI:
    @property
    def name(self):
        return 'ZoomEye'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json',
            'Api-Key': ZOOMEYE_API_KEY
        }

        payload = {
            'query': host,
            'sub_type': 'all'
        }

        r = requests.get(
            'https://api.zoomeye.org/host/search',
            headers=headers,
            params=payload
        )

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['matches']:
            result.append(
                {
                    'port': svc['portinfo']['port'],
                    'service': svc['portinfo']['service'],
                    'transport': svc['protocol']['transport'] or 'tcp',
                    'banner': svc['portinfo']['banner'],
                    'product': svc['portinfo'].get('app', None),
                    'version': svc['portinfo'].get('version', None),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class LeakIXAPI:
    @property
    def name(self):
        return 'LeakIX'


    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json',
            'Api-Key': LEAKIX_API_KEY
        }

        r = requests.get(f'https://leakix.net/host/{host}', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []
        ports = set()

        for svc in data['Services']:
            if svc['port'] in ports:
                continue

            ports.add(svc['port'])

            result.append(
                {
                    'port': svc['port'],
                    'service': svc['protocol'],
                    'transport': svc['transport'][0],
                    'banner': svc['summary'],
                    'product': svc['service']['software']['name'],
                    'version': svc['service']['software']['version'],
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ShodanWeb:
    @property
    def name(self):
        return 'Shodan'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://www.shodan.io/host/{host}',
            'Authority': 'www.shodan.io',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://www.shodan.io/host/{host}/raw', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        match = re.search(r'let data = ({.+});', r.text)

        if not match or not match.group(1):
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: could not extract data.')

            return

        data = None

        try:
            data = yaml.load(match.group(1), Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['data']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['_shodan']['module'],
                    'transport': svc['transport'],
                    'banner': svc['data'],
                    'product': svc.get('product', None),
                    'version': svc.get('version', None),
                    'cpe': svc.get('cpe23', None),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class CensysWeb:
    @property
    def name(self):
        return 'Censys'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://search.censys.io/hosts/{host}',
            'Authority': 'search.censys.io',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://search.censys.io/hosts/{host}/data/json', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        match = re.search(r'<pre><code class="language-json">({.+})</code></pre>', r.text, re.DOTALL)

        if not match or not match.group(1):
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: could not extract data.')

            return

        match_json = match.group(1)
        match_json = re.sub(r'<a (?:href|class)=".*?</a>', '-', match_json)
        match_json = html.unescape(match_json)

        data = None

        try:
            data = yaml.load(match_json, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['services']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service_name'].lower(),
                    'transport': svc['transport_protocol'].lower(),
                    'banner': svc.get('banner', None),
                    'product': svc.get('software', [{}])[0].get('product', None),
                    'version': svc.get('software', [{}])[0].get('version', None),
                    'cpe': svc.get('software', [{}])[0].get(
                        'uniform_resource_identifier', None
                    ),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ZoomEyeWeb:
    @property
    def name(self):
        return 'ZoomEye'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Cube-Authorization': 'auth',
            'Referer': f'https://www.zoomeye.org/searchResult?q=ip%3A%22{referrer}%22',
            'Authority': 'www.zoomeye.org',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        payload = {
            'q': f'ip%3A%22{host}%22',
            'page': '1',
            'pageSize': '20',
            't': 'v4+v6'
        }

        r = requests.get('https://www.zoomeye.org/search', headers=headers, params=payload)

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: HTTP status code is {bred}{r.status_code}{rst}.')

            return

        try:
            search = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        if 'status' in search and search['status'] != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: API status code is {bred}{search[status]}{rst}.')

            return

        if not search.get('matches'):
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: no results.')

            return

        host_token = None
        web_token = None

        for match in search['matches']:
            if host not in match['ip']:
                continue

            if host_token is None and match['type'] == 'host':
                host_token = match['token']

            elif web_token is None and match['type'] == 'web':
                web_token = match['token']

        if web_token is None and host_token is None:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to find tokens in results.')

            return

        token = host_token if host_token is not None else web_token
        host_type = 'host' if host_token is not None else 'web'

        payload = {
            'from': 'detail'
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Cube-Authorization': 'auth',
            'Referer': 'https://www.zoomeye.org/searchDetail?type={host_type}&title={token}',
            'Authority': 'www.zoomeye.org',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://www.zoomeye.org/{host_type}/details/{token}', headers=headers, params=payload)

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        if not data.get('ports'):
            return result

        for svc in data['ports']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service'],
                    'transport': svc['transport'] or 'tcp',
                    'banner': svc['banner'],
                    'product': svc['product'],
                    'version': svc['version'],
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class LeakIXWeb:
    @property
    def name(self):
        return 'LeakIX'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://leakix.net/host/{host}',
            'Authority': 'leakix.net',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }


        if r.status_code != 200:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        tree = etree.HTML(r.text)
        svcs = tree.xpath('//ul[@id="service-panel"]/li')

        ports = {}

        for svc in svcs:
            port = svc.xpath('.//a[starts-with(@href, "/host")]/text()')

            if port:
                port = port[0].split(':')[-1]

            else:
                continue

            banner = svc.xpath('.//pre')

            if banner > 0:
                banner = banner[0].text

            else:
                banner = None

            if port not in ports or not ports[port]:
                ports[port] = banner

        data = []

        softs = tree.xpath('//div[h5[contains(text(), "Software information")]]//div[contains(@class, "list-group-item")]')

        for soft in softs:
            prod = soft.xpath('./p[@class="h5"]/small')

            version = None

            if prod:
                version = prod[0].text
                prod = prod[0].xpath('./preceding-sibling::text()')[-1].strip()

            else:
                prod = None

            svcs = soft.xpath('.//span[contains(@class, "badge")]/text()')

            for svc in svcs:
                svc = svc.split('/')

                data.append({
                    'port': svc[1],
                    'transport': svc[0],
                    'product': prod,
                    'version': version,
                    'banner': ports[svc[1]] if svc[1] in ports else None
                })

        if not data and not ports:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: no services found.')

            return

        for svc in data:
            if svc['port'] in ports:
                del ports[svc['port']]

        for port in ports:
            data.append({
                'port': port,
                'transport': 'tcp',
                'product': None,
                'version': None,
                'banner': ports[port]
            })

        return data

    def enum(self, data):
        result = []

        for svc in data:
            result.append({
                'port': svc['port'],
                'service': None,
                'transport': svc['transport'],
                'banner': svc['banner'],
                'product': svc['product'],
                'version': svc['version'],
                '_source': svc
            })

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class WebScan:
    def merge_results(self, scans):
        def _len(x):
            return len(x) if x is not None else 0

        results = {}

        for name, scan in scans.items():
            for port in scan:
                portname = str(port['port']) + '/' + str(port['transport'])

                if portname not in results:
                    results[portname] = port
                    results[portname]['_source'] = {name: port['_source']}

                else:
                    if _len(port['service']) > _len(results[portname]['service']):
                        results[portname]['service'] = port['service']

                    if _len(port['banner']):
                        if _len(results[portname]['banner']):
                            results[portname]['banner'] += '\n\n' + port['banner']

                        else:
                            results[portname]['banner'] = port['banner']

                    if _len(port['product']) > _len(results[portname]['product']):
                        results[portname]['product'] = port['product']

                    if _len(port['version']) > _len(results[portname]['version']):
                        results[portname]['version'] = port['version']

                    if _len(port.get('cpe', None)) > _len(results[portname].get('cpe', None)):
                        results[portname]['cpe'] = port.get('cpe', None)

                    results[portname]['_source'][name] = port['_source']

        results = sorted(list(results.values()), key=lambda r: int(r['port']))

        return results

    def _scan_host(self, scanner, host, results):
        name = scanner.name

        result = scanner.get(host)

        if result is None:
            error('Failed to get passive scan data for {byellow}{host}{rst}.')

            return

        parsed = scanner.enum(result)

        results[name] = parsed

    def scan_host(self, host):
        info('Getting passive scan data for host {byellow}{host}{rst}...')

        scanners = [ShodanAPI(), CensysAPI(), ZoomEyeAPI(), LeakIXAPI()]
        jobs = []
        results = {}

        for scanner in scanners:
            job = threading.Thread(target=self._scan_host, args=(scanner, host, results))

            jobs.append(job)

            job.start()

        for job in jobs:
            job.join()

        merged = self.merge_results(results)

        if merged:
            info('Total results for host {byellow}{host}{rst}:')

            for svc in merged:
                info('Discovered service {bgreen}{svc[service]}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{svc[transport]}{rst} running {bgreen}{svc[product]}{rst}/{bgreen}{svc[version]}{rst}.')
