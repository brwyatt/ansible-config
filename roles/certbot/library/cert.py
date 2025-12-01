#!/usr/bin/python3
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from typing import Optional, Set, TypedDict
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule


class CertData(TypedDict):
    cert_name: str
    domains: Set[str]


def check_cert(cert_name: str) -> Optional[CertData]:
    cmd = ['certbot', 'certificates', '--noninteractive', '--cert-name', cert_name]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    cert_name_match = re.search(r'^\s*Certificate Name: (.*)$', result.stdout, re.MULTILINE)
    domains_match = re.search(r'^\s*Domains: (.*)$', result.stdout, re.MULTILINE)

    if not cert_name_match or not domains_match:
        return {
            'cert_name': cert_name,
            'domains': set(),
        }

    return {
        'cert_name': cert_name_match.group(1),
        'domains': set(domains_match.group(1).split(" ")),
    }

def main():
    module = AnsibleModule(
        argument_spec={
            'cert_name': {'required': False, 'type': 'str'},
            'domains': {'required': True, 'type': 'list', 'elements': 'str'},
            'state': {'choices': ['present', 'absent'], 'default': 'present', 'type': 'str'},
        },
        supports_check_mode=True
    )

    state = module.params['state']
    requested_domains = module.params['domains']
    requested_domains_set = set(requested_domains)
    if len(requested_domains) < 1:
        module.fail_json(msg="Must request at least one domain!")
    if len(requested_domains) != len(requested_domains_set):
        module.fail_json(msg="Request contains duplicate domains!")
    cert_name = module.params['cert_name']
    if cert_name is None:
        cert_name = requested_domains[0]

    current = check_cert(cert_name)
    if current is None:
        module.fail_json(msg="Failed to check current cert! Is certbot installed?")

    if state == 'present':
        need_change = requested_domains_set != current['domains'],
        if module.check_mode:
            return {
                'changed': need_change,
                'failed': False,
                'cert_name': cert_name,
                'domains_added': requested_domains_set - current['domains'],
                'domains_removed': current['domains'] - requested_domains_set,
            }
        if need_change:
            cmd = [
                "certbot",
                "certonly",
                "--dns-route53",
                "--cert-name",
                cert_name,
                "-d",
                ",".join(requested_domains),
                "--non-interactive",
                "--expand",
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            except (FileNotFoundError, subprocess.CalledProcessError):
                module.fail_json(msg="Certbot command failed! {result}")

            new_cert = check_cert(cert_name)
            return {
                'changed': current['domains'] != new_cert['domains'],
                'failed': False,
                'cert_name': cert_name,
                'domains_added': new_cert['domains'] - current['domains'],
                'domains_removed': current['domains'] - new_cert['domains'],
            }

        return {
            'changed': False,
            'failed': False,
            'cert_name': cert_name,
            'domains_added': [],
            'domains_removed': [],
        }


if __name__ == '__main__':
    main()
