from __future__ import print_function

import optparse
import json
import os
import shutil
import socket
import tempfile
import glob
import time

import irods_python_ci_utilities


def kdc_database_master_key():
    return 'krbtest'

def unprivileged_principal_password():
    return 'krbtest'

def add_alias_to_etc_hosts():
    alias = '.'.join(['icat', 'example', 'org'])

    with tempfile.NamedTemporaryFile() as hosts_copy:
        with open('/etc/hosts', 'r') as hosts_file:
            for l in hosts_file:
                # add the alias to the localhost line so that the server self-identifies as the KDC host
                if '127.0.0.1' in l and alias not in l:
                    hosts_copy.write(f'{l.strip()} {alias}\n'.encode())
                else:
                    hosts_copy.write(l.encode())
        hosts_copy.flush()
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', hosts_copy.name, '/etc/hosts'], check_rc=True)


def install_kerberos_packages_apt():
    debconf_settings = '''
krb5-config	krb5-config/read_conf	boolean	true
krb5-admin-server	krb5-admin-server/newrealm	note
krb5-kdc	krb5-kdc/debconf	boolean	true
krb5-admin-server	krb5-admin-server/kadmind	boolean	true
krb5-kdc	krb5-kdc/purge_data_too	boolean	false
krb5-config	krb5-config/add_servers	boolean	true
krb5-config	krb5-config/add_servers_realm	string	EXAMPLE.ORG
krb5-config	krb5-config/default_realm	string	EXAMPLE.ORG
krb5-config	krb5-config/admin_server	string	icat.example.org
krb5-config	krb5-config/kerberos_servers	string	icat.example.org
'''
    with tempfile.NamedTemporaryFile() as f:
        f.write(debconf_settings.encode())
        f.flush()
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'debconf-set-selections', f.name], check_rc=True)

    irods_python_ci_utilities.install_os_packages(['krb5-admin-server', 'krb5-kdc'])


def install_kerberos_packages_yum():
    irods_python_ci_utilities.install_os_packages(['krb5-server', 'krb5-libs', 'krb5-workstation'])


def install_kerberos_packages():
    dispatch_map = {
        'Ubuntu': install_kerberos_packages_apt,
        'Centos': install_kerberos_packages_yum,
        'Centos linux': install_kerberos_packages_yum
    }
    try:
        return dispatch_map[irods_python_ci_utilities.get_distribution()]()
    except KeyError:
        irods_python_ci_utilities.raise_not_implemented_for_distribution()


def configure_realm_and_domain_apt():
    def create_kerberos_realm():
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'krb5_newrealm'], data='krbtest\nkrbtest\n'.encode(), check_rc=True)

    # add domain to krb5 conf
    def add_domain_to_krb5_conf():
        with tempfile.NamedTemporaryFile() as conf_copy:
            with open('/etc/krb5.conf', 'r') as conf:
                for l in conf:
                    conf_copy.write(l.encode())
                    if '[domain_realm]' in l:
                        conf_copy.write('        .example.org = EXAMPLE.ORG\n'.encode())
                        conf_copy.write('        example.org = EXAMPLE.ORG\n'.encode())
            conf_copy.flush()
            irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', conf_copy.name, '/etc/krb5.conf'], check_rc=True)

    # enable kerberos logging
    def enable_kerberos_logging():
        conf_section = '''
[logging]
        kdc = FILE:/var/log/kerberos/krb5kdc.log
        admin_server = FILE:/var/log/kerberos/kadmin.log
        default = FILE:/var/log/kerberos/krb5lib.log
'''
        with tempfile.NamedTemporaryFile() as conf_copy:
            with open('/etc/krb5.conf', 'r') as conf:
                for l in conf:
                    conf_copy.write(l.encode())
            conf_copy.write(conf_section.encode())
            conf_copy.flush()
            irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', conf_copy.name, '/etc/krb5.conf'], check_rc=True)

        irods_python_ci_utilities.subprocess_get_output(['sudo', 'mkdir', '/var/log/kerberos'], check_rc=True)
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'touch', '/var/log/kerberos/krb5kdc.log'], check_rc=True)
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'touch', '/var/log/kerberos/kadmin.log'], check_rc=True)
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'touch', '/var/log/kerberos/krb5lib.log'], check_rc=True)
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'chmod', '-R', '750', '/var/log/kerberos'], check_rc=True)

    add_domain_to_krb5_conf()
    enable_kerberos_logging()
    create_kerberos_realm()

def configure_realm_and_domain_yum():
    krb5_conf_contents = '''\
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log
[libdefaults]
 default_realm = EXAMPLE.ORG
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
[realms]
 EXAMPLE.ORG = {
  kdc = icat.example.org
  admin_server = icat.example.org
 }
[domain_realm]
 .example.org = EXAMPLE.ORG
 example.org = EXAMPLE.ORG
'''
    with tempfile.NamedTemporaryFile() as conf_copy:
        with open('/etc/krb5.conf', 'r') as krb5_file:
             for l in krb5_file:
                 if 'default_ccache_name' in l:
                     conf_copy.write("#default_ccache_name = KEYRING:persistent:%{uid}".encode())
                 else:
                     conf_copy.write(l.encode())
        conf_copy.write(krb5_conf_contents.encode())
        conf_copy.flush()
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', conf_copy.name, '/etc/krb5.conf'], check_rc=True)

    kdc_conf_contents = '''\
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88
[realms]
 EXAMPLE.ORG = {
  #master_key_type = aes256-cts
  acl_file = /var/kerberos/krb5kdc/kadm5.acl
  dict_file = /usr/share/dict/words
  admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
  supported_enctypes = aes256-cts:normal aes128-cts:normal des3-hmac-sha1:normal arcfour-hmac:normal des-hmac-sha1:normal des-cbc-md5:normal des-cbc-crc:normal
 }
'''
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'chmod', '644', '/var/kerberos/krb5kdc/kdc.conf'], check_rc=True)

    with tempfile.NamedTemporaryFile() as kdcconf_copy:
        with open('/var/kerberos/krb5kdc/kdc.conf', 'r') as kdc_file:
            for l in kdc_file:
                kdcconf_copy.write(l.encode())
        kdcconf_copy.write(kdc_conf_contents.encode())
        kdcconf_copy.flush()
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', kdcconf_copy.name, '/var/kerberos/krb5kdc/kdc.conf'], check_rc=True)

    irods_python_ci_utilities.subprocess_get_output(['sudo', 'kdb5_util', 'create', '-r', 'EXAMPLE.ORG', '-s', '-W'],
                                                    data='{0}\n{0}\n'.format(kdc_database_master_key()).encode(), check_rc=True)


def configure_realm_and_domain():
    dispatch_map = {
        'Ubuntu': configure_realm_and_domain_apt,
        'Centos': configure_realm_and_domain_yum,
        'Centos linux': configure_realm_and_domain_yum
    }
    try:
        return dispatch_map[irods_python_ci_utilities.get_distribution()]()
    except KeyError:
        irods_python_ci_utilities.raise_not_implemented_for_distribution()


def restart_kerberos():
    _, kadmin_pid, _ = irods_python_ci_utilities.subprocess_get_output(['cat', '/var/run/kadmind.pid'])
    _, krb5kdc_pid, _ = irods_python_ci_utilities.subprocess_get_output(['cat', '/var/run/krb5kdc.pid'])

    irods_python_ci_utilities.subprocess_get_output(['kill', kadmin_pid.strip()])
    irods_python_ci_utilities.subprocess_get_output(['kill', krb5kdc_pid.strip()])

    irods_python_ci_utilities.subprocess_get_output(['/usr/sbin/kadmind', '-P', '/var/run/kadmind.pid'], check_rc=True)
    irods_python_ci_utilities.subprocess_get_output(['/usr/sbin/krb5kdc', '-P', '/var/run/krb5kdc.pid'], check_rc=True)


def create_privileged_principal():
    stdin = '''addprinc root/admin
krbtest
krbtest
'''
    irods_python_ci_utilities.subprocess_get_output(['sudo','kadmin.local'], data=stdin.encode(), check_rc=True)


def enable_admin_privileges_apt():
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'chmod', '775', '/etc/krb5kdc'], check_rc=True)
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'chmod', '644', '/etc/krb5kdc/kadm5.acl'], check_rc=True)
    with tempfile.NamedTemporaryFile() as kadm5_copy:
        with open('/etc/krb5kdc/kadm5.acl', 'r') as kadm5_file:
            for l in kadm5_file:
                kadm5_copy.write(l.encode())
        kadm5_copy.write('*/admin *\n'.encode())
        kadm5_copy.flush()
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', kadm5_copy.name, '/etc/krb5kdc/kadm5.acl'], check_rc=True)


def enable_admin_privileges_yum():
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'chmod', '644', '/var/kerberos/krb5kdc/kadm5.acl'], check_rc=True)
    with tempfile.NamedTemporaryFile() as kadm5_copy:
        with open('/var/kerberos/krb5kdc/kadm5.acl', 'r') as kadm5_file:
            for l in kadm5_file: 
                 kadm5_copy.write(l.encode())
        kadm5_copy.write('*/admin@EXAMPLE.ORG *\n'.encode())
        kadm5_copy.flush()       
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'cp', kadm5_copy.name, '/var/kerberos/krb5kdc/kadm5.acl'], check_rc=True)


def enable_admin_privileges():
    dispatch_map = {
        'Ubuntu': enable_admin_privileges_apt,
        'Centos': enable_admin_privileges_yum,
        'Centos linux': enable_admin_privileges_yum
    }
    try:
        return dispatch_map[irods_python_ci_utilities.get_distribution()]()
    except KeyError:
        irods_python_ci_utilities.raise_not_implemented_for_distribution()


def create_unprivileged_principal(principal):
    stdin = '''{0}
addprinc {1}
{2}
{2}
'''.format(kdc_database_master_key(), principal, unprivileged_principal_password())
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'kadmin', '-p', 'root/admin'], data=stdin.encode(), check_rc=True)


def create_keytab():
    stdin = '''krbtest
ktadd -k /var/lib/irods/irods.keytab irods/icat.example.org@EXAMPLE.ORG
'''
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'kadmin', '-p', 'root/admin'], data=stdin.encode(), check_rc=True)
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'chown', 'irods:irods', '/var/lib/irods/irods.keytab'],
                                                    check_rc=True)


def update_irods_server_config():
    with open('/etc/irods/server_config.json') as f:
        d = json.load(f)
    d['KerberosServicePrincipal'] = 'irods/icat.example.org@EXAMPLE.ORG'
    d['KerberosKeytab'] = '/var/lib/irods/irods.keytab'  # Not actually used, read from the environment variable
    d['environment_variables']['KRB5_KTNAME'] = '/var/lib/irods/irods.keytab'
    with open('/etc/irods/server_config.json', 'w') as f:
        json.dump(d, f, indent=4, sort_keys=True)


def restart_irods():
    if irods_python_ci_utilities.get_irods_version() >= (4, 2):
        irods_python_ci_utilities.subprocess_get_output(
            ['sudo', 'su', '-', 'irods', '-c', '/var/lib/irods/irodsctl restart'], check_rc=True)
    else:
        irods_python_ci_utilities.subprocess_get_output(
            ['sudo', 'su', '-', 'irods', '-c', '/var/lib/irods/iRODS/irodsctl restart'], check_rc=True)


def create_ticket_granting_ticket():
    irods_python_ci_utilities.subprocess_get_output(['sudo', 'kinit', 'krb_user'],
                                                    data='{0}\n'.format(unprivileged_principal_password()).encode(),
                                                    check_rc=True)


def create_json_config_file_for_unit_test():
    _, out, _ = irods_python_ci_utilities.subprocess_get_output(['sudo', 'klist'], check_rc=True)
    first_line = out.split('\n')[0]
    ticket_cache = first_line.rpartition('Ticket cache: ')[2]
    d = {'client_user_principal': 'krb_user@EXAMPLE.ORG',
         'client_user_ticket_cache': ticket_cache}
    
    with open('/tmp/krb5_test_cfg.json', 'w') as f:
        json.dump(d, f, indent=4, sort_keys=True)

    ticket_cache_file = ticket_cache.rpartition('FILE:')[2]
    irods_python_ci_utilities.subprocess_get_output(['sudo','chmod', 'o+r', ticket_cache_file], check_rc=True)


def install_testing_dependencies():
    irods_python_ci_utilities.subprocess_get_output(['sudo', '-EH', 'python3', '-m', 'pip', 'install', 'unittest-xml-reporting==1.14.0'])

    install_kerberos_packages()


def configure_kerberos_for_testing():
    configure_realm_and_domain()
    restart_kerberos()

    create_privileged_principal()
    enable_admin_privileges()
    restart_kerberos()

    create_unprivileged_principal('krb_user')
    create_unprivileged_principal('irods/icat.example.org')
    create_keytab()
    create_ticket_granting_ticket()
    create_json_config_file_for_unit_test()


def main():
    parser = optparse.OptionParser()
    parser.add_option('--output_root_directory')
    parser.add_option('--built_packages_root_directory')
    parser.add_option('--test', metavar='dotted name')
    parser.add_option('--skip-setup', action='store_false', dest='do_setup', default=True)
    options, _ = parser.parse_args()

    built_packages_root_directory = options.built_packages_root_directory
    package_suffix = irods_python_ci_utilities.get_package_suffix()
    os_specific_directory = irods_python_ci_utilities.append_os_specific_directory(built_packages_root_directory)

    if options.do_setup:
        irods_python_ci_utilities.install_os_packages_from_files(
            glob.glob(os.path.join(os_specific_directory,
                      f'irods-auth-plugin-krb*.{package_suffix}')
            )
        )

        add_alias_to_etc_hosts()

        install_testing_dependencies()

        configure_kerberos_for_testing()

    test = options.test or 'test_irods_auth_plugin_krb'

    try:
        test_output_file = 'log/test_output.log'
        irods_python_ci_utilities.subprocess_get_output(['sudo', 'su', '-', 'irods', '-c',
            f'python3 scripts/run_tests.py --xml_output --run_s={test} 2>&1 | tee {test_output_file}; exit $PIPESTATUS'],
            check_rc=True)
    finally:
        output_root_directory = options.output_root_directory
        if output_root_directory:
            irods_python_ci_utilities.gather_files_satisfying_predicate('/var/lib/irods/log', output_root_directory,
                                                                        lambda x: True)
            shutil.copy('/var/lib/irods/log/test_output.log', output_root_directory)
            shutil.copytree('/var/lib/irods/test-reports', os.path.join(output_root_directory, 'test-reports'))


if __name__ == '__main__':
    main()
