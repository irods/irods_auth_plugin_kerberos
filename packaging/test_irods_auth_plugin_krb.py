import os
import commands
import time

import sys
if sys.version_info >= (2,7):
    import unittest
else:
    import unittest2 as unittest

import lib
from resource_suite import ResourceBase


class Test_Kerberos(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(Test_Kerberos, self).setUp()
        keytabFileSource = "~/secrets/kerberos/irods.keytab"
        keytabFileDest = "/var/lib/irods/irods.keytab"
        hostname = lib.get_hostname()
        serverConfig = "/etc/irods/server.config"
        irodsUser = "rods"
        irodsUserDN = "irods@IRODS.RENCI.ORG"

        # Copy the keytab file to the irods install area
        os.system("cp %s %s" % (keytabFileSource, keytabFileDest))
        os.system("chmod 600 %s" % keytabFileDest)

        # Edit the server config to set the name of the irods service
        print "iRODS Server Hostname: ", hostname
        os.system("echo \"KerberosServicePrincipal irods-server/%s@IRODS.RENCI.ORG\" >> %s" % (hostname, serverConfig))
        os.system("echo \"KerberosKeytab %s\" >> %s" % (keytabFileDest, serverConfig))

        # Add the user authentication
        os.system("iadmin aua %s %s" % (irodsUser, irodsUserDN))

        self.prev_auth_scheme = os.environ.get('IRODS_AUTHENTICATION_SCHEME', None)
        os.environ['IRODS_AUTHENTICATION_SCHEME'] = 'krb'

    def tearDown(self):
        if self.prev_auth_scheme:
            os.environ['IRODS_AUTHENTICATION_SCHEME'] = self.prev_auth_scheme
        super(Test_Kerberos, self).tearDown()

    # Try to authenticate before getting a TGT. Make sure this fails.
    def test_authentication_krb_without_tgt(self):
        # Destroy any existing TGT's
        os.system("kdestroy")

        # Try an ils and make sure it fails
        self.admin.assert_icommand("ils", 'STDERR_SINGLELINE', "KRB_ERROR_ACQUIRING_CREDS")

    # Try to authenticate after getting a TGT. This should pass
    def test_authentication_krb_with_tgt(self):
        krbPassword = "thisisnotasecret"

        # Make sure we have a valid TGT
        os.system("echo Password: \"%s\"" % krbPassword)
        os.system("echo %s | kinit" % krbPassword)

        # Try an ils
        self.admin.assert_icommand("ils", 'STDOUT_SINGLELINE', "home")
