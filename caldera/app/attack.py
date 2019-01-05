#!/bin/env python

import argparse
import datetime
import logging
import re
from requests import Session
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3 import disable_warnings
import sys
import time
disable_warnings(InsecureRequestWarning)


class CalderaClient(object):
    def __init__(self, url, username, password, proxies=None):
        self.url = url
        self.session = Session()
        self.username = username
        self.password = password
        self.proxies = proxies
        if self.proxies:
            # proxies = {
            #     'http': 'http://127.0.0.1:8081',
            #     'https': 'https://127.0.0.1:8081',
            # }
            self._update_proxies()
        self._login()
    def _login(self):
        data = {
            "username" : self.username,
            "password" : self.password
        }
        return self._request('POST', 'login', data)
    def _update_proxies(self, proxy):
        self.session.proxies.update(self.proxies)
    def _find_from_list_by_key(self, l, key, value):
        result = list(filter(lambda x:x[key]==value, l))
        if len(result) == 0:
            return None
        return result[0]
    # oid 使うケースと名前を使うケースを分けたほうがいいか. 人間が直接オブジェクトを呼び出す場合は名前だが、参照オブジェクトのから被参照オブジェクトを呼び出す場合は oid 使うわな
    def adversaries(self, oid=None, name=None):
        if oid:
            query = 'api/adversaries/{}'.format(oid)
            l = self._request('GET', query, None).json()
        else:
            l = self._request('GET', 'api/adversaries', None).json()
            if name:
                return self._find_from_list_by_key(l, "name", name)
        return l
    def networks(self, oid=None, name=None):
        if oid:
            query = 'api/networks/{}'.format(oid)
            l = self._request('GET', query, None).json()
        else:
            l = self._request('GET', 'api/networks', None).json()
            if name:
                return self._find_from_list_by_key(l, "name", name)
        return l
    def domains(self, name=None):
        l = self._request('GET', 'api/domains', None).json()
        if name:
            return self._find_from_list_by_key(l, "name", name)
        return l
    def hosts(self, oid=None, network=None, name=None):
        query = 'api/hosts'
        if network:
            query = 'api/networks/{}/hosts'.format(network['_id'])
            if oid:
                query += '/{}'.format(oid)
        l = self._request('GET', query, None).json()
        if name:
            return self._find_from_list_by_key(l, "hostname", name)
        return l
    def operations(self, name=None):
        query = 'api/operations'
        l = self._request('GET', query, None).json()
        if name:
            return self._find_from_list_by_key(l, "name", name)
        return l
    def jobs(self, job_id):
        query = 'api/jobs/{}'.format(job_id)
        j = self._request('GET', query, None).json()
        return j
    def run_operation(self,
                  name,
                  adversary,
                  network,
                  start_host,
                  start_path,
                  start_type = "bootstrap",
                  user_type = "system",
                  perform_cleanup = True,
                  delay = 0,
                  jitter = 0
                  ):
        query = 'api/networks/{}/operations'.format(network['_id'])
        data = {
            "name":name,
            "start_host":start_host["_id"],
            "adversary":adversary["_id"],
            "start_type":start_type,
            "user_type":user_type,
            "perform_cleanup":perform_cleanup,
            "delay":delay,
            "jitter":jitter,
            "start_path":start_path
        }
        operation_id = self._request('POST', query, data).json()
        query = 'api/networks/{}/operations/{}'.format(network['_id'], operation_id)
        return self._request('GET', query, None).json()
    def delete_operation(self, network, operation):
        query = 'api/networks/{}/operations/{}'.format(network['_id'], operation['_id'])
        return self._request('DELETE', query, None).json()

    def _observed_something(self, what, oid=None):
        query = 'api/observed/{}'.format(what)
        if oid:
            query += '/{}'.format(oid)
        return self._request('GET', query, None).json()
    def observed_credentials(self, oid=None):
        return self._observed_something('credentials', oid)
    def observed_users(self, oid=None):
        return self._observed_something('users', oid)
    def observed_shares(self, oid=None):
        return self._observed_something('shares', oid)
    def observed_files(self, oid=None):
        return self._observed_something('files', oid)
    def observed_domains(self, oid=None):
        return self._observed_something('domains', oid)
    def observed_os_versions(self, oid=None):
        return self._observed_something('os_versions', oid)
    def observed_hosts(self, oid=None):
        return self._observed_something('hosts', oid)
    def observed_schtasks(self, oid=None):
        return self._observed_something('schtasks', oid)
    def observed_services(self, oid=None):
        return self._observed_something('services', oid)
    def observed_timedeltas(self, oid=None):
        return self._observed_something('timedeltas', oid)
    def observed_rats(self, oid=None):
        return self._observed_something('rats', oid)
    def observed_registry_keys(self, oid=None):
        return self._observed_something('registry_keys', oid)
    def observed_persistence(self, oid=None):
        return self._observed_something('persistence', oid)
    def observed_processes(self, oid=None):
        return self._observed_something('processes', oid)
    def _request(self, method, path, data):
        h = {"Accept": "application/json",
             "Content-type": "application/json; charset=utf-8"
        }
        r = self.session.request(
            method, self.url + path, headers=h, verify=False, json=data
        )
        r.raise_for_status()
        return r

class Operation(object):
    client = None
    users = None
    domains = None
    os_versions = None
    def dict_to_string(self, dct):
        return ', '.join(['{} : {}'.format(key, value) for (key, value) in dct.items()])
    def domain_to_string(self, domain):
        dct = {}
        for key in domain.keys():
            if key in ['_id']:
                pass
            else:
                dct[key] = domain[key]
        return self.dict_to_string(dct)
    def host_to_string(self, host):
        dct = {}
        for key in host.keys():
            if key in ['admins', 'local_profiles']:
                dct[key] = [self.users[uid]['username'] for uid in host[key]]
            elif key in ['_id', 'processes', 'system_info']:
                pass
            else:
                dct[key] = host[key]
        return self.dict_to_string(dct)
    def user_to_string(self, user):
        dct = {}
        for key in user.keys():
            if key in ['domain']:
                dct[key] = self.domains[user[key]]['windows_domain']
            elif key in ['_id']:
                pass
            else:
                dct[key] = user[key]
        return self.dict_to_string(dct)
    def credential_to_string(self, credential):
        dct = {}
        for key in credential.keys():
            if key in ['found_on_host']:
                dct[key] = self.hosts[credential[key]]['hostname']
            elif key in ['user']:
                dct[key] = self.users[credential[key]]['username']
            elif key in ['_id']:
                pass
            else:
                dct[key] = credential[key]
        return self.dict_to_string(dct)
    def persistence_to_string(self, persistence):
        dct = {}
        for key in persistence.keys():
            if key == 'host':
                dct[key] = self.hosts[persistence[key]]['hostname']
            elif key == 'regkey_artifact':
                dct[key] = self.client.observed_registry_keys(persistence[key])
            elif key == 'service_artifact':
                dct[key] = self.client.observed_services(persistence[key])
            elif key in ['_id']:
                pass
            else:
                dct[key] = persistence[key]
        return self.dict_to_string(dct)
    def build(self, client, operation):
        self.client = client
        self.operation = operation
        self.adversary = self.client.adversaries(oid=self.operation['adversary'])
        self.network = self.client.networks(oid=self.operation['network'])
        self.domains = {}
        for domainid in operation['known_domains']:
            self.domains[domainid] = self.client.observed_domains(domainid)
        self.hosts = {}
        for hostid in operation['known_hosts']:
            self.hosts[hostid] = self.client.observed_hosts(hostid)
        self.users = {}
        for userid in operation['known_users']:
            self.users[userid] = self.client.observed_users(userid)
        self.os_versions = {}
        for os_versionid in operation['known_os_versions']:
            self.os_versions[os_versionid] = self.client.observed_os_versions(os_versionid)
        
    def report_operation(self):
        # 
        # status
        # reason
        # start_type
        # start_host -> host
        # start_time
        observables = [
            "credentials",#user, host
            "domains",#*
            "files",
            "hosts",#host
            "os_versions",#host
            "persistence",#host, registry_key, service
            "processes",
            "rats",
            "registry_keys",
            "schtasks",
            "services",
            "shares",
            "timedeltas",
            "users",#user
        ]
        # for observed in observables:
        #     print(observed)
        # 1つのオペレーションで現れるドメインは1つしかないでしょう
        # わざわざここで host でくくる必要あるだろうか。必要な観点ではあるが。必要ということにしておく
        for key in ['status', 'reason', 'start_type', 'start_time']:
            print("{} {}".format(key, self.operation[key]))
        start_host = self.client.hosts(
            oid=self.operation['start_host'], network=self.network)
        print("start_host {}".format(start_host['hostname']))
        # operation の各ステップが成功したかどうかの確認。そもそも実行に失敗している場合がある.
        # この文脈だと、条件が合わずに実行できなかったステップも整理したほうがいいよな.
        # for fileid in operation['known_files']:
        #     print(client.observed_files())
        for step in self.operation['performed_steps']:
            # ここで name, description, status, と以下の追加確認事項を追加すればよいな。
            # print(step['name'])
            for job_id in step['jobs']:
                job = self.client.jobs(job_id)
                output = job['action']['result']['stdout']
                #defender の real time scan でこれが出てくる
                if re.search("This script contains malicious content and has been blocked by your antivirus software.", output):
                    LOGGER.error('{} seems to be failed by antivirus'.format(step['name']))
                elif re.search("The term '[-\w]+' is not recognized as the name of a cmdlet, function, script file, or operable program.", output):
                    LOGGER.error('{} seems to be failed by antivirus'.format(step['name']))
                elif re.search("ERROR: The parameter is incorrect.", output):
                    LOGGER.error('{} seems to be failed by antivirus'.format(step['name']))
                # get_admin で output が空なのもpost conditionにマッチしないから失敗だな。
                # powersploit/powerview の Get-NetLocalGroupMember をリモートで指定してもだめらしいから、管理権限がだめなんだろか
        for (oid, domain) in self.domains.items():
            print(self.domain_to_string(domain))
        for (oid, host) in self.hosts.items():
            print(self.host_to_string(host))
        for (oid, user) in self.users.items():
            print(self.user_to_string(user))
        for credentialid in self.operation['known_credentials']:
            credential = self.client.observed_credentials(credentialid)
            print(self.credential_to_string(credential))
        for persistenceid in self.operation['known_persistence']:
            persistence = self.client.observed_persistence(persistenceid)
            print(self.persistence_to_string(persistence))

def main(op_name, ad_name, run, wait, report):
    """
    caldera にアクセスして、指定された operation の動作を確認するために必要な情報を excel にまとめたい
    """
    c = CalderaClient('https://caldera:8888/', 'admin', 'caldera')
    o = None
    if run:
        o = c.operations(op_name)
        if o is not None:
            LOGGER.error('operation {} already exists'.format(op_name))
            sys.exit(1)
        a = c.adversaries(name=ad_name)
        n = c.networks(name="nw")
        h = c.hosts(network=n, name="desktop")
        o = c.run_operation(op_name, a, n, h, 'C:\\commander.exe')
        print(o)
    if wait:
        o = c.operations(op_name)
        if o is None:
            LOGGER.error('operation {} not found'.format(op_name))
            sys.exit(1)
        while o['status'] in ['start', 'started', 'running']:
            LOGGER.info('waiting {}'.format(o['status']))
            time.sleep(60)
            o = c.operations(op_name)
        LOGGER.info('done {}'.format(o['status']))
    if report:
        o = c.operations(op_name)
        if o is None:
            LOGGER.error('operation {} not found'.format(op_name))
            sys.exit(1)
        op = Operation()
        op.build(c, o)
        op.report_operation()

# "start_time":"2018-11-26T17:54:48.786000+00:00",
# "start_type":"bootstrap",
# "status":"complete",

# "start_time":"2018-12-22T08:28:30.123000+00:00",
# "start_type":"bootstrap",
# "status":"complete",
# "reason":"Stop was requested",

LOGGER = logging.getLogger(__name__)    
if __name__ == '__main__':
    # python attack.py -a 'Bob (Built-in)' -r -w $(date +'%FT%T') 
    # python attack.py -w '2018-12-25T00:41:43'
    logging.basicConfig(stream=sys.stderr)
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.debug(datetime.datetime.now().strftime("%FT%T"))
    parser = argparse.ArgumentParser()
    parser.add_argument('operation_name',
                        help='operation name')
    parser.add_argument('--adversary_name', '-a', default='Lazarus Group (Built-in)',
                        help='adversary name')
    parser.add_argument('--run', '-r', action='store_true',
                        help='run operation')
    parser.add_argument('--wait', '-w', action='store_true',
                        help='wait operation')
    parser.add_argument('--no-report', dest='report', action='store_false',
                        help='generate report')
    args = parser.parse_args()
    main(args.operation_name, args.adversary_name, args.run, args.wait, args.report)
    #python attack.py $(data +'%FT%T')
else:
    LOGGER.setLevel(logging.INFO)

def getnetlocalgroupmember(text):
    try:
        users = []
        skip = text.find("ComputerName")
        safe = text[skip:]
        for block in safe.split("\r\n\r\n"):
            lines = block.splitlines()
            parsed_block = {}
            for line in lines:
                if ':' in line:
                    k, v = line.split(':')
                    parsed_block[k.strip()] = v.strip().lower()
                else:
                    continue
            # block_dict = {x.strip(): y.strip() for x, y in line.split(':') for line in lines}
            if len(parsed_block):
                domain, user = parsed_block.get('MemberName').split('\\')
                users.append(dict(username=user,
                                  is_group=(True if parsed_block.get('IsGroup', '') == "True" else False),
                                  sid=parsed_block.get('SID', ''),
                                  windows_domain=domain, host=parsed_block.get('ComputerName', '')))
        return users
    except:
        raise ParseError("Unexpected Data in return: {}".format(text))

def getnetlocalgroupmember_json(text):
    try:
        raw_data = json.loads(text.lower())
        users = []
        for raw_user in raw_data:
            domainname, username = raw_user['membername'].split('\\')
            user = 
            users.append({
                'username' : username,
                'is_group' : raw_user['isgroup'],
                'sid' : raw_user['sid'],
                'windows_domain' : domainname,
                'host' : raw_user['computername']
            })
        return users
    except:
        raise ParseError("Unexpected Data in return: {}".format(text))

def getnetgroupmember(text):
    try:
        users = []
        skip = text.find("GroupDomain")
        safe = text[skip:]
        for block in safe.split("\r\n\r\n"):
            lines = block.splitlines()
            parsed_block = {}
            for line in lines:
                if ':' in line:
                    k, v = line.split(':')
                    parsed_block[k.strip()] = v.strip().lower()
                else:
                    continue
            # block_dict = {x.strip(): y.strip() for x, y in line.split(':') for line in lines}
            if len(parsed_block):
                if parsed_block.get('MemberObjectClass', '') != 'user':
                    next
                domain = parsed_block.get('GroupDomain', '')
                user = parsed_block.get('MemberName', '')
                users.append(dict(username=user,
                                  is_group=False,
                                  sid=parsed_block.get('MemberSID', ''),
                                  windows_domain=domain))
        return users
    except:
        raise ParseError("Unexpected Data in return: {}".format(text))

getnetgroupmember(text)

text = open("gnlgm.txt").read()
getnetlocalgroupmember(text)

text = open("gngm.txt", "rb").read().decode("utf-8")
getnetgroupmember(text)

import json
j = open("gnlgm.json").read().lower()
getnetlocalgroupmember_json(open("gnlgm.json").read())
