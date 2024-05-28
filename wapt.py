"""WAPT Integration"""

import os
import json
import logging
import tempfile
from fuzzywuzzy import fuzz
from requests.auth import HTTPBasicAuth
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
wapt_url = CONF.get('cyberwatch', 'wapt_server_url')
wapt_user = CONF.get('cyberwatch', 'wapt_user')
wapt_password = CONF.get('cyberwatch', 'wapt_password')
key = SSLPrivateKey(CONF.get('cyberwatch', 'ssl_pem_location'), password=CONF.get(
    'cyberwatch', 'wapt_ssl_key'))
cert_path = SSLCertificate(CONF.get('cyberwatch', 'ssl_cert_location'))
prefix = CONF.get('cyberwatch', 'prefix')

ssl_pem_client_location = CONF.get('cyberwatch', 'ssl_pem_client_location')
ssl_cert_client_location = CONF.get('cyberwatch', 'ssl_cert_client_location')

# Cyberwatch Conf
url = CONF.get('cyberwatch', 'url')
access_key = CONF.get('cyberwatch', 'access_key')
secret_key = CONF.get('cyberwatch', 'secret_key')

dict_name_soft = json.loads(CONF.get('cyberwatch', 'software_dict'))

def search_uuid(computername):
    """Search for UUID with hostname"""
    try:
        url = f'{wapt_url}/api/v1/hosts?filter=computer_name:{computername}&reachable=1&columns=uuid,computer_name&limit=2000'
        response = requests.get(url, auth=(wapt_user, wapt_password), verify=False, cert=(ssl_cert_client_location, ssl_pem_client_location))
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


def find_software_dict(software_dict, soft_name):
    for key in software_dict:
        if key in soft_name:
            return software_dict[key]

def is_approximate_match(str1, str2, threshold=80):
    result = fuzz.token_sort_ratio(str1, str2) > threshold
    return result

def find_software(data, soft_name):
    for software in data['result']:
        if software.get('name') in soft_name or software.get('package') in soft_name:
            logging.warning("Package found on machine")
            return software

    response = requests.get(f'{wapt_url}/api/v3/packages', auth=(wapt_user,wapt_password),verify=False,cert=(ssl_cert_client_location, ssl_pem_client_location))

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
    session = requests.Session()
    session.verify = False

    try:
        login_request = session.post(
            '%s/api/v3/login' % wapt_url, json={'user': wapt_user, 'password': wapt_password})        
        login_request.raise_for_status()  # This will log HTTP error codes automatically
        auth = login_request.json()
        if not auth['success']:
            error_msg = 'Login error: %s' % auth['msg']
            logging.error(error_msg)
            raise Exception(error_msg)
        else:
            logging.warning("Login successful")
    except requests.exceptions.RequestException as e:
        logging.exception("Request failed: %s", e)

    uuid = search_uuid(hostname)

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
    response = requests.get(f'{wapt_url}/api/v1/host_data?uuid={uuid}&field=installed_packages', auth=(wapt_user,wapt_password),verify=False,cert=(ssl_cert_client_location, ssl_pem_client_location))

    result = find_software(response.json(), soft_name)

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

        action_request = requests.post(
            '%s/api/v3/trigger_host_action' % wapt_url, json=actions,auth=(wapt_user,wapt_password),verify=False,cert=(ssl_cert_client_location, ssl_pem_client_location))

        action_request.raise_for_status()

        pe_req = requests.get('%s/%s.wapt' % (repo_url, uuid),auth=(wapt_user,wapt_password),verify=False,cert=(ssl_cert_client_location, ssl_pem_client_location))
        tmp_fn = tempfile.mktemp(prefix="wapt")
        if pe_req.status_code == 404 :
            package_entry = PackageEntry(package=result,section='host', verify=False,auth=(wapt_user,wapt_password),cert=(ssl_cert_client_location, ssl_pem_client_location))
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
            package_entry.sign_package(cert_path, key)

            # upload
            upload_request = requests.post('%s/api/v3/upload_packages' % wapt_url, files={os.path.basename(new_fn): open(package_entry.localpath,
                                            'rb').read()},auth=(wapt_user,wapt_password),verify=False,cert=(ssl_cert_client_location, ssl_pem_client_location))
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
