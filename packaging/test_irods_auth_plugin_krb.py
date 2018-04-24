import os
import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest
import shutil
import json

from . import session
from .. import lib
from ..controller import IrodsController


def ils_output_to_entries(stdout):
    raw = stdout.strip().split('\n')
    collection = raw[0]
    entries = [entry.strip() for entry in raw[1:]]
    return entries

def files_in_ils_output(ils_out):
    for item in ils_out:
        # strip collections
        if not item.startswith('C- /'):
            yield item

# JSON config file must have:
#    'client_user_principal'
#    'client_user_ticket_cache'
#    get both from klist
CFG_FILE_PATH = '/tmp/krb5_test_cfg.json'

class Test_Authentication(unittest.TestCase):

    '''Tests kerberos authentication for a regular user.
    '''

    def setUp(self):
        super(Test_Authentication, self).setUp()

        with open('/etc/irods/server_config.json') as f:
            d = json.load(f)
        if 'KRB5_KTNAME' not in d['environment_variables']:
            d['KerberosServicePrincipal'] = 'irods/icat.example.org@EXAMPLE.ORG'
            d['KerberosKeytab'] = '/var/lib/irods/irods.keytab'  # Not actually used, read from the environment variable
            d['environment_variables']['KRB5_KTNAME'] = '/var/lib/irods/irods.keytab'
            with open('/etc/irods/server_config.json', 'w') as f:
                json.dump(d, f, indent=4, sort_keys=True)
            IrodsController().restart()
 
        # load configuration from file
        with open(CFG_FILE_PATH) as cfg_file:
            self.config = json.load(cfg_file)

        # local test dir
        self.testing_tmp_dir = '/tmp/irods_Test_Authentication'
        shutil.rmtree(self.testing_tmp_dir, ignore_errors=True)
        os.mkdir(self.testing_tmp_dir)

        # admin sesh
        self.admin = session.make_session_for_existing_admin()

        # make new user with no password
        self.krb_username = 'krb_user'
        self.krb_user = session.mkuser_and_return_session(
            'rodsuser', self.krb_username, None, lib.get_hostname())

        # set auth scheme for new user (client side)
        self.krb_user.environment_file_contents[
            'irods_authentication_scheme'] = 'krb'

        # set auth string for new user (server side)
        self.admin.run_icommand(['iadmin', 'aua', self.krb_username, self.config['client_user_principal']])

    def tearDown(self):
        # exit user sesh
        self.krb_user.__exit__()

        # remove krb user
        self.admin.run_icommand(['iadmin', 'rmuser', self.krb_username])

        # exit admin sesh
        self.admin.__exit__()

        # remove local test dir
        shutil.rmtree(self.testing_tmp_dir)

        super(Test_Authentication, self).tearDown()

    def test_ils(self):
        # set client env
        env = os.environ.copy()
        env['KRB5CCNAME'] = self.config['client_user_ticket_cache']

        self.krb_user.assert_icommand(
            'ils', 'STDOUT_SINGLELINE', self.krb_user.home_collection, env=env)

    def test_irsync_r_nested_dir_to_coll(self):
        # test settings
        depth = 10
        files_per_level = 100
        file_size = 100

        # make local nested dirs
        base_name = "test_irsync_r_nested_dir_to_coll"
        local_dir = os.path.join(self.testing_tmp_dir, base_name)
        local_dirs = lib.make_deep_local_tmp_dir(
            local_dir, depth, files_per_level, file_size)

        # set client env
        env = os.environ.copy()
        env['KRB5CCNAME'] = self.config['client_user_ticket_cache']

        # sync dir to coll
        self.krb_user.assert_icommand(
            "irsync -r {local_dir} i:{base_name}".format(**locals()), "EMPTY", env=env)

        # compare files at each level
        for directory, files in local_dirs.iteritems():
            partial_path = directory.replace(self.testing_tmp_dir + '/', '', 1)

            # run ils on subcollection
            self.krb_user.assert_icommand(
                ['ils', partial_path], 'STDOUT_SINGLELINE', env=env)
            ils_out = ils_output_to_entries(
                self.krb_user.run_icommand(['ils', partial_path], env=env)[0])

            # compare local files with irods objects
            local_files = set(files)
            rods_files = set(files_in_ils_output(ils_out))
            self.assertTrue(local_files == rods_files,
                            msg="Files missing:\n" + str(local_files - rods_files) + "\n\n" +
                            "Extra files:\n" + str(rods_files - local_files))

        # cleanup
        self.krb_user.assert_icommand(
            "irm -rf {base_name}".format(**locals()), "EMPTY", env=env)

    def test_irsync_r_nested_dir_to_coll_large_files(self):
        # test settings
        depth = 4
        files_per_level = 4
        file_size = 1024 * 1024 * 40

        # make local nested dirs
        base_name = "test_irsync_r_nested_dir_to_coll"
        local_dir = os.path.join(self.testing_tmp_dir, base_name)
        local_dirs = lib.make_deep_local_tmp_dir(
            local_dir, depth, files_per_level, file_size)

        # set client env
        env = os.environ.copy()
        env['KRB5CCNAME'] = self.config['client_user_ticket_cache']

        # sync dir to coll
        self.krb_user.assert_icommand(
            "irsync -r {local_dir} i:{base_name}".format(**locals()), "EMPTY", env=env)

        # compare files at each level
        for directory, files in local_dirs.iteritems():
            partial_path = directory.replace(self.testing_tmp_dir + '/', '', 1)

            # run ils on subcollection
            self.krb_user.assert_icommand(
                ['ils', partial_path], 'STDOUT_SINGLELINE', env=env)
            ils_out = ils_output_to_entries(
                self.krb_user.run_icommand(['ils', partial_path], env=env)[0])

            # compare local files with irods objects
            local_files = set(files)
            rods_files = set(files_in_ils_output(ils_out))
            self.assertTrue(local_files == rods_files,
                            msg="Files missing:\n" + str(local_files - rods_files) + "\n\n" +
                            "Extra files:\n" + str(rods_files - local_files))

        # cleanup
        self.krb_user.assert_icommand(
            "irm -rf {base_name}".format(**locals()), "EMPTY", env=env)
