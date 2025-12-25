from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from typing import Optional, TypedDict
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule


kerberos_principal_regex = re.compile(
    r'^\s*(?P<kvno>\d+)\s+'
    r'(?P<principal>'
    r'(?P<primary>[^/]+)/'
    r'(?P<instance>[^@]+)@'
    r'(?P<realm>[\w\.]+))\s*$'
)

class CertData(TypedDict):
    cert_name: str
    present: bool
    status: Optional[str]
    stuck: Optional[bool]
    key_path: Optional[str]
    cert_path: Optional[str]
    subject_cn: Optional[str]
    domain: Optional[str]
    track: Optional[bool]
    auto_renew: Optional[bool]


def check_cert(cert_name: str) -> CertData:
    cmd = ['ipa-getcert', 'list', '--id', cert_name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise RuntimeError(f"ipa-getcert failed: {e}")
    if (
        result.returncode == 1 and
        "No request found with specified nickname" in result.stdout
    ):
        return {
            'cert_name': cert_name,
            'present': False,
            "status": None,
            "stuck": None,
            "key_path": None,
            "cert_path": None,
            "subject_cn": None,
            "domain": None,
            "track": None,
            "auto_renew": None,
        }
    cert_name_match = re.search(r'^Request ID \'(.*)\':$', result.stdout, re.MULTILINE)
    status_match = re.search(r'^\s*status: (.+)$', result.stdout, re.MULTILINE)
    stuck_match = re.search(r'^\s*stuck: (yes|no)$', result.stdout, re.MULTILINE)
    key_match = re.search(r'^\s*key pair storage: type=FILE,location=\'(.*)\'$', result.stdout, re.MULTILINE)
    cert_match = re.search(r'^\s*certificate: type=FILE,location=\'(.*)\'$', result.stdout, re.MULTILINE)
    subject_cn_match = re.search(r'^\s*subject: .*CN\s*=\s*([^,\n]+)(?:,.*)?$', result.stdout, re.MULTILINE)
    domain_match = re.search(r'^\s*dns: (.+)$', result.stdout, re.MULTILINE)
    track_match = re.search(r'^\s*track: (yes|no)$', result.stdout, re.MULTILINE)
    auto_renew_match = re.search(r'^\s*auto-renew: (yes|no)$', result.stdout, re.MULTILINE)
    return {
        'cert_name': cert_name_match.group(1),
        'present': True,
        'status': status_match.group(1) if status_match else None,
        'stuck': (stuck_match.group(1) == "yes") if stuck_match else None,
        'key_path': key_match.group(1) if key_match else None,
        'cert_path': cert_match.group(1) if cert_match else None,
        'subject_cn': subject_cn_match.group(1).lower() if subject_cn_match else None,
        'domain': domain_match.group(1).lower() if domain_match else None,
        'track': (track_match.group(1) == "yes") if track_match else None,
        'auto_renew': (auto_renew_match.group(1) == "yes") if auto_renew_match else None,
    }


def delete_cert(cert_name: str) -> None:
    cmd = ['ipa-getcert', 'stop-tracking', '--id', cert_name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise RuntimeError(f"ipa-getcert failed: {e}")

def request_cert(cert_name: str, cert_path: str, key_path: str, principal: str, domain: str) -> CertData:
    cmd = [
        'ipa-getcert', 'request',
        '--new-id', cert_name,
        '--certfile', cert_path,
        '--keyfile', key_path,
        '--principal', principal,
        '--dns', domain,
        '--subject-name', domain,
        '--cert-perms', '0644',
        '--wait',
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise RuntimeError(f"ipa-getcert failed: {e}")


def get_host_principal():
    try:
        cmd = ['klist', '-k', '/etc/krb5.keytab']
        out = subprocess.check_output(cmd, text=True)
        for line in out.splitlines():
            match = re.match(kerberos_principal_regex, line)
            if match and match.group("primary") == "host":
                return match.group("principal")
    except Exception:
        return None


def main():
    module = AnsibleModule(
        argument_spec={
            'cert_name': {'required': True, 'type': 'str'},
            'domain': {'required': False, 'type': 'str'},
            'principal': {'required': False, 'type': 'str'},
            'cert_path': {'required': False, 'type': 'str'},
            'key_path': {'required': False, 'type': 'str'},
            'state': {'choices': ['present', 'absent'], 'default': 'present', 'type': 'str'},
        },
        supports_check_mode=True
    )

    state = module.params['state'].lower()
    cert_name = module.params['cert_name']
    domain = module.params['domain']
    if state == "present":
        if domain is None or domain == "":
            module.fail_json(msg="`domain` must be defined when `state` is \"present\"")
        else:
            domain = domain.lower()
    principal = module.params['principal']
    if principal is None or principal == "":
        principal = get_host_principal()
    cert_path = module.params['cert_path']
    if state == "present" and (cert_path is None or cert_path == ""):
        module.fail_json(msg="`cert_path` must be defined when `state` is \"present\"")
    key_path = module.params['key_path']
    if state == "present" and (key_path is None or key_path == ""):
        module.fail_json(msg="`key_path` must be defined when `state` is \"present\"")

    requested_state =  {
        'cert_name': cert_name,
        'present': False,
        "status": None,
        "stuck": None,
        "key_path": None,
        "cert_path": None,
        "subject_cn": None,
        "domain": None,
        "track": None,
        "auto_renew": None,
    }
    if state == "present":
        requested_state = {
            'cert_name': cert_name,
            'present': True,
            "status": "MONITORING",
            "stuck": False,
            "key_path": key_path,
            "cert_path": cert_path,
            "subject_cn": domain,
            "domain": domain,
            "track": True,
            "auto_renew": True,
        }

    try:
        original_state = check_cert(cert_name)
    except RuntimeError as e:
        module.fail_json(msg=f"{e}")

    need_change = requested_state != original_state

    if module.check_mode:
        module.exit_json(**{
            'changed': need_change,
            'failed': False,
            'original_state': original_state,
            'new_state': requested_state,
        })

    if original_state["present"] and need_change:
        # either we're removing a cert or we're changing it (and need to delete first)
        try:
            delete_cert(cert_name)
        except RuntimeError as e:
            module.fail_json(msg=f"{e}")

    if requested_state["present"] and need_change:
        try:
            request_cert(cert_name, cert_path, key_path, principal, domain)
        except RuntimeError as e:
            module.fail_json(msg=f"{e}")

    new_state = check_cert(cert_name)
    changed = original_state != new_state
    failed = new_state != requested_state

    module.exit_json(**{
        'changed': changed,
        'failed': failed,
        'original_state': original_state,
        'new_state': new_state,
        'requested_state': requested_state,
    })


if __name__ == '__main__':
    main()
