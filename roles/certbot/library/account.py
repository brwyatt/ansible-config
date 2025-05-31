#!/usr/bin/env python3
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule


regexs = {
    'server': re.compile(r'^Account details for server (.*)$'),
    'account_url': re.compile(r'^  Account URL: (.*)$'),
    'thumbprint': re.compile(r'^  Account Thumbprint: (.*)$'),
    'email': re.compile(r'^  Email contact: (.*)$'),
}


def query():
    data = {
        'registered': False,
        'server': None,
        'account_url': None,
        'thumbprint': None,
        'email': None,
    }

    try:
        result = subprocess.run(['certbot', 'show_account'], capture_output=True, text=True)
    except FileNotFoundError:
        return data

    if result.returncode != 0:
        return data

    for line in result.stdout.split('\n'):
        for name, regex in regexs.items():
            match = regex.match(line)
            if match:
                data[name] = match[1]
                break

    data['registered'] = None not in data.values()

    return data


def main():
    module = AnsibleModule(
        argument_spec={
            'email': {'required': True, 'type': 'str'},
            'state': {'choices': ['registered', 'query'], 'default': 'registered', 'type': 'str'},
        },
        supports_check_mode=True
    )

    email = module.params['email']
    state = module.params['state']

    data = {
        'changed': False,
        'failed': False,
        **query(),
    }
    result = {**data}

    if state == 'registered':
        if not module.check_mode:
            if not data['registered']:
                try:
                    ret = subprocess.run(['certbot', 'register', '--agree-tos', '--email', email], capture_output=True, text=True)
                except Exception:
                    result['failed'] = True
            elif data['email'] != email:
                try:
                    ret = subprocess.run(['certbot', 'update_account', '--email', email], capture_output=True, text=True)
                except Exception:
                    result['failed'] = True
            result = {
                **result,
                **query(),
            }
            result['changed'] = data['email'] != result['email'] or data['thumbprint'] != result['thumbprint']
        else:
            result = {
                **data,
                'email': email,
                'registered': True,
                'changed': data['email'] != email,
            }
    elif state == 'query':
        pass

    module.exit_json(**result)

if __name__ == '__main__':
    main()
