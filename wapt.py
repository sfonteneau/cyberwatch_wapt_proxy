"""WAPT Integration"""

import os
import json
import logging
import tempfile
from fuzzywuzzy import fuzz
import waptlicences
from configparser import ConfigParser
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys
sys.path.append('/opt/wapt')
from waptcrypto import SSLCertificate, SSLPrivateKey
from waptpackage import PackageEntry
from waptutils import ensure_list
from common import get_requests_client_cert_session
from common import Wapt
from flask import Flask, request

app = Flask(__name__)

# Configure logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

CONF = ConfigParser()
CONF.read(os.path.join(os.path.abspath(
    os.path.dirname(__file__)), '.', 'integration.conf'))

ini_wapt_path = CONF.get('cyberwatch', 'waptgetini')
w = Wapt(config_filename=ini_wapt_path)

# WAPT Conf
wapt_url = w.waptserver.server_url
key = SSLPrivateKey(CONF.get('cyberwatch', 'ssl_pem_location'), password=CONF.get(
    'cyberwatch', 'wapt_ssl_key'))
cert_path = SSLCertificate(CONF.get('cyberwatch', 'ssl_cert_location'))
prefix = CONF.get('cyberwatch', 'prefix')

# Cyberwatch Conf
url = CONF.get('cyberwatch', 'url')
access_key = CONF.get('cyberwatch', 'access_key')
secret_key = CONF.get('cyberwatch', 'secret_key')

dict_name_soft = json.loads(CONF.get('cyberwatch', 'software_dict'))

def search_uuid(computername,session):
    """Search for UUID with hostname"""
    try:
        url = f'{wapt_url}/api/v3/hosts?filter=computer_name:{computername}&reachable=1&columns=uuid,computer_name&limit=2000'
        response = session.get(url)
        # logging.error(response.status_code)
        if response.status_code == 200:
            try:
                data = response.json()
                for asset in data['result']:
                    if asset['computer_name'].lower() == computername.lower():
                        return asset['uuid']
                return "Asset not found"  # Return not found after checking all assets
            except requests.exceptions.JSONDecodeError:
                print("Received non-JSON response from the server.")
                return None  # Return None or raise an exception if JSON decoding fails
        else:
            print("Request failed with status code:", response.status_code)
            return None  # Return None if the request itself failed
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return None  # Return None or handle specific exceptions if needed


def get_session_wapt(user,password):
    t = waptlicences.waptserver_login(ini_wapt_path,user,password)
    s = get_requests_client_cert_session(wapt_url,
    cert=(t['client_certificate'],t['client_private_key'],t['client_private_key_password']),
    verify=w.waptserver.verify_cert
    )
    s.cookies.set(t['session_cookies'][0]['Name'], t['session_cookies'][0]['Value'], domain=t['session_cookies'][0]['Domain'])
    t= None
    return s

def find_software_dict(software_dict, soft_name):
    for key in software_dict:
        if key in soft_name:
            return software_dict[key]

def is_approximate_match(str1, str2, threshold=80):
    result = fuzz.token_sort_ratio(str1, str2) > threshold
    return result

def find_software(data, soft_name,s):
    for software in data['result']:
        if software.get('name') in soft_name or software.get('package') in soft_name:
            logging.warning("Package found on machine")
            return software

    response = s.get(f'{wapt_url}/api/v3/packages')

    response_data = response.json()

    for soft in soft_name:
        for software_data in response_data["result"]:
            prefixed = prefix + "-" + soft
            # logging.warning(software_data)
            if  soft == software_data["name"].lower() or prefixed == software_data["package"].lower():
                logging.warning("Package found in repo but not pushed yet on machine")
                return software_data
            if  is_approximate_match(soft.lower(), software_data["name"].lower()) or is_approximate_match(prefixed.lower(), software_data["package"].lower()):
                logging.warning("Package found in repo with fuzz but not pushed yet on machine")
                return software_data
        else:
            logging.warning("Package not found, trying dictionnary method")
            dict = find_software_dict(dict_name_soft, soft_name)
            if dict:
                logging.warning("Package found with dictionnary method")
                filtered_data = [entry for entry in response_data["result"] if entry.get("package") == dict]
                return filtered_data[0]

# Install package with WAPT
@app.route('/install_package', methods=['POST'])
def install_package():
    """Install package with WAPT"""

    action = 'trigger_install_packages'

    name = request.get_json()
    hostname = request.get_json()['hostname']
    soft_name = [name['product'].lower().strip()]

    try:
        ##################################################
        CONF = ConfigParser()
        CONF.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), '.', 'integration.conf'))
        password = CONF.get('cyberwatch', 'wapt_password')
        #################################################
        s = get_session_wapt(CONF.get('cyberwatch', 'wapt_user'),password)
    except requests.exceptions.RequestException as e:
        logging.exception("Request failed: %s", e)

    uuid = search_uuid(hostname,s)

    data = requests.get(f"{url}/api/v3/assets/servers?hostname={hostname}", headers={"Accept": "application/json; charset=utf-8"}, auth=(access_key, secret_key), verify=False).json()
    cbw_id = [item['id'] for item in data if item['category'] in ['server', 'desktop']]
    full = requests.get(f"{url}/api/v3/vulnerabilities/servers/{cbw_id[0]}", headers={"Accept": "application/json; charset=utf-8"}, auth=(access_key, secret_key), verify=False).json()

    for update in full['updates']:
        if update['current'] :
            if soft_name[0].lower() == update['current']['product'].lower():
                soft_name.append(update['target']['product'].lower())
            if soft_name[0].lower() == update['target']['product'].lower():
                soft_name.append(update['current']['product'].lower())

    # Send GET request
    response = s.get(f'{wapt_url}/api/v3/host_data?uuid={uuid}&field=installed_packages')

    result = find_software(response.json(), soft_name,s)

    package = result['package']

    logging.error(package)


    if package is not None :
        actions = []

        action = {
            'uuid': uuid,
            'action': 'trigger_host_update',
            'notify_server': True,
        }

        actions.append(key.sign_claim(action, signer_certificate_chain=[cert_path]))

        action = {
            'uuid': uuid,
            'action': "trigger_install_packages",
            'packages': [package],
            'force': False,
            'notify_server': True,
        }

        repo_url = '%s/wapt-host' % wapt_url

        actions.append(key.sign_claim(action, signer_certificate_chain=[cert_path]))

        action_request = s.post(
            '%s/api/v3/trigger_host_action' % wapt_url, json=actions)

        action_request.raise_for_status()

        pe_req = s.get('%s/%s.wapt' % (repo_url, uuid))
        tmp_fn = tempfile.mktemp(prefix="wapt")
        if pe_req.status_code == 404 :
            package_entry = PackageEntry(package=uuid,section='host')
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
            print(package_entry)
            new_fn = package_entry.build_management_package()

            waptlicences.sign_package(new_fn,CONF.get('cyberwatch', 'ssl_cert_location'),CONF.get('cyberwatch', 'ssl_pem_location'),CONF.get('cyberwatch', 'wapt_ssl_key'))

            # upload
            upload_request = s.post('%s/api/v3/upload_packages' % wapt_url, files={os.path.basename(new_fn): open(package_entry.localpath,'rb').read()})
            upload_request.raise_for_status()
            upload_result = upload_request.json()
            if not upload_result['success']:
                raise Exception('Erreur upload: %s' % upload_result['msg'])
            return upload_result

        finally:
            if os.path.isfile(tmp_fn):
                os.unlink(tmp_fn)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
