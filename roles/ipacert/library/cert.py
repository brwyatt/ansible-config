from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from typing import Optional, Set, TypedDict
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
            'cert_name': {'required': False, 'type': 'str'},
            'domain': {'required': False, 'type': 'str'},
            'principal': {'required': False, 'type': 'str'},
            'state': {'choices': ['present', 'absent'], 'default': 'present', 'type': 'str'},
        },
        supports_check_mode=True
    )

    state = module.params['state']
    cert_name = module.params['cert_name']
    principal = module.params['principal']
    if principal is None or principal == "":
        principal = get_host_principal()


if __name__ == '__main__':
    main()
