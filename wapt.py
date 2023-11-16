"""WAPT Integration"""

import os
import logging
import tempfile
from configparser import ConfigParser
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
sys.path.append('/opt/wapt')
from waptcrypto import SSLCertificate, SSLPrivateKey
from waptpackage import PackageEntry
from waptutils import ensure_list

from flask import Flask, request

app = Flask(__name__)

# Configure logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

CONF = ConfigParser()
CONF.read(os.path.join(os.path.abspath(
    os.path.dirname(__file__)), '.', 'integration.conf'))

# WAPT Conf
wapt_server_url = CONF.get('cyberwatch', 'wapt_server_url')
wapt_user = CONF.get('cyberwatch', 'wapt_user')
wapt_password = CONF.get('cyberwatch', 'wapt_password')
key = SSLPrivateKey(CONF.get('cyberwatch', 'ssl_pem_location'), password=CONF.get(
    'cyberwatch', 'wapt_ssl_key'))
cert = SSLCertificate(CONF.get('cyberwatch', 'ssl_cert_location'))
prefix = CONF.get('cyberwatch', 'prefix')

# Cyberwatch Conf
url = CONF.get('cyberwatch', 'url')
access_key = CONF.get('cyberwatch', 'access_key')
secret_key = CONF.get('cyberwatch', 'secret_key')

def search_uuid(session, computername):
    """Search for UUID with hostname"""
    response = session.get('%s/api/v3/hosts?filter=computer_fqdn:%s&reachable=1&columns=computer_fqdn,uuid,computer_name&limit=2000' %
                           (wapt_server_url, computername)).json()
    for asset in response['result']:
        if asset['computer_name'].lower() == computername.lower():
            return asset['uuid']
        else:
            return "Asset not found"

def find_software(data, soft_name):
    for software in data['result']:
        if software.get('name') in soft_name or software.get('package') in soft_name:
            return  software

    response = requests.get(f'{wapt_server_url}/api/v3/packages', auth=(wapt_user, wapt_password), verify=False)
    response_data = response.json()
    for software_data in response_data["result"]:
        for soft in soft_name:
            prefixed = prefix + "-" + soft
            if  soft == software_data["name"] or prefixed == software_data["package"]:
                logging.warning("Package found in repo but not pushed yet on machine")
                return software_data
    return None


# Install package with WAPT

action = 'trigger_install_packages'

name = request.get_json()
hostname = request.get_json()['hostname']
soft_name = [name['product'].lower().strip()]
session = requests.Session()
session.verify = False

login_request = session.post(
    '%s/api/v3/login' % wapt_server_url, json={'user': wapt_user, 'password': wapt_password})
login_request.raise_for_status()
auth = login_request.json()
if not auth['success']:
    raise Exception('Erreur login: %s' % auth['msg'])

uuid = search_uuid(session, hostname)

data = requests.get(f"{url}/api/v3/assets/servers?hostname={hostname}", headers={"Accept": "application/json; charset=utf-8"}, auth=(access_key, secret_key), verify=False).json()
cbw_id = [item['id'] for item in data if item['category'] in ['server', 'desktop']]
full = requests.get(f"{url}/api/v3/vulnerabilities/servers/{cbw_id[0]}", headers={"Accept": "application/json; charset=utf-8"}, auth=(access_key, secret_key), verify=False).json()

for update in full['updates']:
    if update['current'] :
        if soft_name[0] == update['current']['product']:
            soft_name.append(update['target']['product'])
        if soft_name[0] == update['target']['product']: 
            soft_name.append(update['current']['product'])

# Send GET request
response = requests.get(f'{wapt_server_url}/api/v1/host_data?uuid={uuid}&field=installed_packages', auth=(wapt_user, wapt_password), verify=False)

logging.warning(soft_name)
result = find_software(response.json(), soft_name)
package = soft_name
actions = []

action = {
    'uuid': uuid,
    'action': 'trigger_host_update',
    'notify_server': True,
}

actions.append(key.sign_claim(action, signer_certificate_chain=[cert]))

action = {
    'uuid': uuid,
    'action': "trigger_install_packages",
    'packages': [package],
    'force': False,
    'notify_server': True,
}    

repo_url = '%s/wapt-host' % wapt_server_url
logging.warning(action)

actions.append(key.sign_claim(action, signer_certificate_chain=[cert]))

action_request = session.post(
    '%s/api/v3/trigger_host_action' % wapt_server_url, json=actions)
action_request.raise_for_status()

pe_req = session.get('%s/%s.wapt' % (repo_url, uuid), verify=False)
tmp_fn = tempfile.mktemp(prefix="wapt")
if pe_req.status_code == 404 :
    package_entry = PackageEntry(package=result,section='host', verify=False)
    package_entry.save_control_to_wapt(tmp_fn)
else:
    pe_req.raise_for_status()
    pe_data = pe_req.content
    with open(tmp_fn, 'wb') as file:
        file.write(pe_data)
    package_entry = PackageEntry(waptfile=tmp_fn)

try:
    depends = ensure_list(package_entry.depends)
    if not package in depends:
        depends.append(package)
    package_entry.depends = ','.join(depends)
    package_entry.inc_build()
    package_entry.save_control_to_wapt()
    new_fn = package_entry.build_management_package()
    package_entry.sign_package(cert, key)

    # upload
    upload_request = session.post('%s/api/v3/upload_packages' % wapt_server_url,
                                    files={os.path.basename(new_fn): open(package_entry.localpath, 'rb').read()})
    upload_request.raise_for_status()
    upload_result = upload_request.json()
    if not upload_result['success']:
        raise Exception('Erreur upload: %s' % upload_result['msg'])

finally:
    if os.path.isfile(tmp_fn):
        os.unlink(tmp_fn)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)