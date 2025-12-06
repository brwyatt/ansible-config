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
    present: bool


def check_cert(cert_name: str) -> CertData:
    cmd = ['certbot', 'certificates', '--noninteractive', '--cert-name', cert_name]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise RuntimeError(f"Certbot failed: {e}")

    cert_name_match = re.search(r'^\s*Certificate Name: (.*)$', result.stdout, re.MULTILINE)
    domains_match = re.search(r'^\s*Domains: (.*)$', result.stdout, re.MULTILINE)

    if not cert_name_match or not domains_match:
        return {
            'cert_name': cert_name,
            'domains': set(),
            'present': False,
        }

    return {
        'cert_name': cert_name_match.group(1),
        'domains': set(domains_match.group(1).split(" ")),
        'present': True,
    }

def main():
    module = AnsibleModule(
        argument_spec={
            'cert_name': {'required': False, 'type': 'str'},
            'domains': {'required': False, 'type': 'list', 'elements': 'str'},
            'state': {'choices': ['present', 'absent'], 'default': 'present', 'type': 'str'},
        },
        supports_check_mode=True
    )

    state = module.params['state']
    requested_domains = module.params['domains']
    requested_domains_set = set(requested_domains)
    if state == "present" and len(requested_domains) < 1:
        module.fail_json(msg="Must request at least one domain if state is 'present'!")
    if len(requested_domains) != len(requested_domains_set):
        module.fail_json(msg="Request contains duplicate domains!")
    cert_name = module.params['cert_name']
    if cert_name is None or cert_name == "":
        cert_name = requested_domains[0]

    try:
        current = check_cert(cert_name)
    except RuntimeError as e:
        module.fail_json(msg=f"{e}")

    if state == 'present':
        need_change = (
            (not current['present']) or
            (requested_domains_set != current['domains'])
        )
        if module.check_mode:
            return {
                'changed': need_change,
                'failed': False,
                'cert_name': cert_name,
                'domains_added': list(requested_domains_set - current['domains']),
                'domains_removed': list(current['domains'] - requested_domains_set),
            }
        if not need_change:
            return {
                'changed': False,
                'failed': False,
                'cert_name': cert_name,
                'domains_added': [],
                'domains_removed': [],
            }

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
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            module.fail_json(
                msg=f"Certbot command failed during execution: {e}",
                stdout=e.stdout if hasattr(e, 'stdout') else None,
                stderr=e.stderr if hasattr(e, 'stderr') else None,
            )

        try:
            new_cert = check_cert(cert_name)
        except RuntimeError as e:
            module.fail_json(msg=f"{e}")
        return {
            'changed': current['domains'] != new_cert['domains'],
            'failed': False,
            'cert_name': cert_name,
            'domains_added': list(new_cert['domains'] - current['domains']),
            'domains_removed': list(current['domains'] - new_cert['domains']),
        }

    if state == "absent":
        need_change = current['present']
        if module.check_mode:
            return {
                'changed': need_change,
                'failed': False,
                'cert_name': cert_name,
                'domains_added': [],
                'domains_removed': list(current['domains']),
            }

        if not need_change:
            return {
                'changed': False,
                'failed': False,
                'cert_name': cert_name,
                'domains_added': [],
                'domains_removed': [],
            }

        cmd = [
            "certbot",
            "delete",
            "--cert-name",
            cert_name,
            "--non-interactive",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            module.fail_json(
                msg=f"Certbot command failed during execution: {e}",
                stdout=e.stdout if hasattr(e, 'stdout') else None,
                stderr=e.stderr if hasattr(e, 'stderr') else None,
            )

        try:
            new_cert = check_cert(cert_name)
        except RuntimeError as e:
            module.fail_json(msg=f"{e}")
        return {
            'changed': current['domains'] != new_cert['domains'],
            'failed': False,
            'cert_name': cert_name,
            'domains_added': list(new_cert['domains'] - current['domains']),
            'domains_removed': list(current['domains'] - new_cert['domains']),
        }


if __name__ == '__main__':
    main()
