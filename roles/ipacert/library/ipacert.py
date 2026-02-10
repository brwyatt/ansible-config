from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import os
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
    key_owner: Optional[str]
    key_perms: Optional[str]
    cert_path: Optional[str]
    cert_owner: Optional[str]
    cert_perms: Optional[str]
    subject_cn: Optional[str]
    domain: Optional[str]
    track: Optional[bool]
    auto_renew: Optional[bool]
    after_command: Optional[str]


def parse_storage_line(line: str):
    """Parses a storage line like:
    key pair storage: type=FILE,location='/path/to/key',owner='user',perms=0600
    or
    certificate: type=FILE,location='/path/to/cert',owner=rabbitmq,perms=0644
    """
    location = None
    owner = None
    perms = None
    
    # Improved regex for location: handles optional quotes
    loc_match = re.search(r"location=['\"]?([^'\",]+)['\"]?", line)
    if loc_match:
        location = loc_match.group(1)
        
    # Improved regex for owner: handles optional quotes
    owner_match = re.search(r"owner=['\"]?([^'\",]+)['\"]?", line)
    if owner_match:
        owner = owner_match.group(1)
        
    # Improved regex for perms: handles optional quotes
    perms_match = re.search(r"perms=['\"]?([0-7]+)['\"]?", line)
    if perms_match:
        perms = perms_match.group(1)
        
    return location, owner, perms

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
            "key_owner": None,
            "key_perms": None,
            "cert_path": None,
            "cert_owner": None,
            "cert_perms": None,
            "subject_cn": None,
            "domain": None,
            "track": None,
            "auto_renew": None,
            "after_command": None,
        }
    
    cert_name_match = re.search(r'^Request ID \'(.*)\':$', result.stdout, re.MULTILINE)
    status_match = re.search(r'^\s*status: (.+)$', result.stdout, re.MULTILINE)
    stuck_match = re.search(r'^\s*stuck: (yes|no)$', result.stdout, re.MULTILINE)
    
    key_line_match = re.search(r'^\s*key pair storage: (.*)$', result.stdout, re.MULTILINE)
    key_path, key_owner, key_perms = parse_storage_line(key_line_match.group(1)) if key_line_match else (None, None, None)
    
    cert_line_match = re.search(r'^\s*certificate: (.*)$', result.stdout, re.MULTILINE)
    cert_path, cert_owner, cert_perms = parse_storage_line(cert_line_match.group(1)) if cert_line_match else (None, None, None)
    
    subject_cn_match = re.search(r'^\s*subject: .*CN\s*=\s*([^,\n]+)(?:,.*)?$', result.stdout, re.MULTILINE)
    domain_match = re.search(r'^\s*dns: (.+)$', result.stdout, re.MULTILINE)
    track_match = re.search(r'^\s*track: (yes|no)$', result.stdout, re.MULTILINE)
    auto_renew_match = re.search(r'^\s*auto-renew: (yes|no)$', result.stdout, re.MULTILINE)
    
    after_cmd_match = re.search(r'^\s*post-save command: (.*)$', result.stdout, re.MULTILINE)
    after_command = after_cmd_match.group(1).strip() if after_cmd_match else None
    if after_command == "":
        after_command = None

    return {
        'cert_name': cert_name_match.group(1) if cert_name_match else cert_name,
        'present': True,
        'status': status_match.group(1) if status_match else None,
        'stuck': (stuck_match.group(1) == "yes") if stuck_match else None,
        'key_path': key_path,
        'key_owner': key_owner,
        'key_perms': key_perms,
        'cert_path': cert_path,
        'cert_owner': cert_owner,
        'cert_perms': cert_perms,
        'subject_cn': subject_cn_match.group(1).lower() if subject_cn_match else None,
        'domain': domain_match.group(1).lower() if domain_match else None,
        'track': (track_match.group(1) == "yes") if track_match else None,
        'auto_renew': (auto_renew_match.group(1) == "yes") if auto_renew_match else None,
        'after_command': after_command,
    }


def delete_cert(cert_name: str) -> None:
    cmd = ['ipa-getcert', 'stop-tracking', '--id', cert_name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise RuntimeError(f"ipa-getcert failed: {e}")

def request_cert(cert_name, cert_path, key_path, principal, domain, 
                 cert_owner=None, cert_perms=None, key_owner=None, key_perms=None, 
                 after_command=None):
    cmd = [
        'ipa-getcert', 'request',
        '--id', cert_name,
        '--certfile', cert_path,
        '--keyfile', key_path,
        '--principal', principal,
        '--dns', domain,
        '--subject-name', domain,
        '--wait',
    ]
    if cert_owner:
        cmd.extend(['--cert-owner', cert_owner])
    if cert_perms:
        cmd.extend(['--cert-perms', cert_perms])
    if key_owner:
        cmd.extend(['--key-owner', key_owner])
    if key_perms:
        cmd.extend(['--key-perms', key_perms])
    if after_command:
        cmd.extend(['--after-command', after_command])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise RuntimeError(f"ipa-getcert failed: {e.stderr if hasattr(e, 'stderr') else e}")


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
            'cert_owner': {'required': False, 'type': 'str'},
            'cert_perms': {'required': False, 'type': 'str'},
            'key_path': {'required': False, 'type': 'str'},
            'key_owner': {'required': False, 'type': 'str'},
            'key_perms': {'required': False, 'type': 'str'},
            'after_command': {'required': False, 'type': 'str'},
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
            return
        else:
            domain = domain.lower()
    principal = module.params['principal']
    if principal is None or principal == "":
        principal = get_host_principal()
    cert_path = module.params['cert_path']
    if state == "present" and (cert_path is None or cert_path == ""):
        module.fail_json(msg="`cert_path` must be defined when `state` is \"present\"")
        return
    key_path = module.params['key_path']
    if state == "present" and (key_path is None or key_path == ""):
        module.fail_json(msg="`key_path` must be defined when `state` is \"present\"")
        return

    try:
        original_state = check_cert(cert_name)
    except Exception as e:
        module.fail_json(msg=f"Failed to check current state: {e}")
        return

    requested_state = original_state.copy()
    if state == "absent":
        requested_state['present'] = False
    else:
        requested_state.update({
            'present': True,
            'cert_path': cert_path,
            'key_path': key_path,
            'domain': domain,
            'subject_cn': domain,
        })
        # Only update requested state with these if they are provided by the user
        if module.params['cert_owner'] is not None:
            requested_state['cert_owner'] = module.params['cert_owner']
        if module.params['cert_perms'] is not None:
            requested_state['cert_perms'] = module.params['cert_perms']
        if module.params['key_owner'] is not None:
            requested_state['key_owner'] = module.params['key_owner']
        if module.params['key_perms'] is not None:
            requested_state['key_perms'] = module.params['key_perms']
        if module.params['after_command'] is not None:
            requested_state['after_command'] = module.params['after_command']

    # Smart comparison: we only care about differences in fields that are either 
    # core (present, path, domain) or were explicitly requested by the user.
    need_change = False
    if original_state['present'] != requested_state['present']:
        need_change = True
    elif state == "present":
        # Check core fields
        if original_state['cert_path'] != requested_state['cert_path'] or \
           original_state['key_path'] != requested_state['key_path'] or \
           original_state['domain'] != requested_state['domain']:
            need_change = True
        
        # Check optional fields ONLY if provided by user
        if not need_change:
            for field in ['cert_owner', 'cert_perms', 'key_owner', 'key_perms', 'after_command']:
                if module.params[field] is not None and original_state[field] != module.params[field]:
                    need_change = True
                    break

    if module.check_mode:
        module.exit_json(**{
            'changed': need_change,
            'failed': False,
            'original_state': original_state,
            'new_state': requested_state,
        })
        return

    if original_state["present"] and need_change:
        # either we're removing a cert or we're changing it (and need to delete first)
        try:
            delete_cert(cert_name)
        except Exception as e:
            module.fail_json(msg=f"Failed to delete cert tracking: {e}")
            return
        # Only remove files if we are actually making a change that requires it
        try:
            os.remove(original_state['cert_path'])
        except (FileNotFoundError, TypeError, KeyError):
            pass
        except Exception as e:
            module.fail_json(msg=f"Failed to remove cert file: {e}")
            return
        try:
            os.remove(original_state['key_path'])
        except (FileNotFoundError, TypeError, KeyError):
            pass
        except Exception as e:
            module.fail_json(msg=f"Failed to remove key file: {e}")
            return

    if requested_state["present"] and need_change:
        try:
            request_cert(
                cert_name, cert_path, key_path, principal, domain,
                cert_owner=module.params['cert_owner'],
                cert_perms=module.params['cert_perms'],
                key_owner=module.params['key_owner'],
                key_perms=module.params['key_perms'],
                after_command=module.params['after_command']
            )
        except Exception as e:
            module.fail_json(msg=f"Failed to request cert: {e}")
            return

    try:
        new_state = check_cert(cert_name)
    except Exception as e:
        module.fail_json(msg=f"Failed to check new state: {e}")
        return

    # Changed if something actually changed on the system
    changed = False
    if original_state['present'] != new_state['present']:
        changed = True
    elif original_state['present'] and new_state['present']:
        for field in ['cert_path', 'key_path', 'domain', 'cert_owner', 'cert_perms', 'key_owner', 'key_perms', 'after_command']:
            if original_state.get(field) != new_state.get(field):
                changed = True
                break
                
    # Failed if the new state doesn't match what we wanted for the fields we care about
    failed = False
    if new_state['present'] != requested_state['present']:
        failed = True
    elif requested_state['present']:
        for field in ['cert_path', 'key_path', 'domain']:
            if new_state.get(field) != requested_state.get(field):
                failed = True
                break
        if not failed:
            for field in ['cert_owner', 'cert_perms', 'key_owner', 'key_perms', 'after_command']:
                if module.params[field] is not None and new_state.get(field) != module.params[field]:
                    failed = True
                    break

    module.exit_json(**{
        'changed': changed,
        'failed': failed,
        'original_state': original_state,
        'new_state': new_state,
        'requested_state': requested_state,
    })
    return


if __name__ == '__main__':
    main()
