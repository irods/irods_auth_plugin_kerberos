import sys
if (sys.version_info >= (2,7)):
    import unittest
else:
    import unittest2 as unittest
from pydevtest_common import assertiCmd, assertiCmdFail, getiCmdOutput, create_local_testfile, get_hostname
import pydevtest_sessions as s
from resource_suite import ResourceBase
import os
import commands
import time
import socket

class Test_Kerberos_Suite(unittest.TestCase, ResourceBase):
    
    my_test_resource = {"setup":[], "teardown":[]}

    def setUp(self):
        ResourceBase.__init__(self)
        s.twousers_up()
        self.run_resource_setup()

    def tearDown(self):
        self.run_resource_teardown()
        s.twousers_down()

    # Configure iRODS to enable kerberos support. Note it will not be turned on until the appropriate environment variable is set
    def kerberos_setup(self):

        keytabFileSource = "~/secrets/kerberos/irods.keytab"
        keytabFileDest = "/var/lib/irods/irods.keytab"
        hostname = socket.gethostname()
        serverConfig = "/etc/irods/server.config"
        irodsUser = "rods"
        irodsUserDN = "irods@IRODS.RENCI.ORG"

        # Copy the keytab file to the irods install area
        os.system("cp %s %s" % (keytabFileSource, keytabFileDest))
        os.system("chmod 600 %s" % keytabFileDest)

        # Edit the server config to set the name of the irods service
        os.system("echo \"KerberosServicePrincipal irods-server\/%s@IRODS.RENCI.ORG\" >> %s" % (hostname, serverConfig))
        os.system("echo \"KerberosKeytab %s\" >> %s" % (keytabFileDest, serverConfig))

        # Add the user authentication
        os.system("iadmin aua %s %s" % (irodsUser, irodsUserDN))

        # Set the appropriate environment variables
        os.environ['irodsAuthScheme'] = "krb"

    # Try to authenticate before getting a TGT. Make sure this fails.
    def test_authentication_krb_without_tgt(self):

        self.kerberos_setup()

        # Destroy any existing TGT's
        os.system("kdestroy -A")

        # Try an ils and make sure it fails
        assertiCmdFail(s.adminsession, "ils", "LIST", "home")

    # Try to authenticate after getting a TGT. This should pass
    def test_authentication_krb_with_tgt(self):
        krbPassword = "thisisnotasecret"

        self.kerberos_setup()

        # Make sure we have a valid TGT
        os.system("echo Password: \"%s\"" % krbPassword)
        os.system("echo %s | kinit" % krbPassword)

        # Try an ils
        assertiCmd(s.adminsession, "ils", "LIST", "home")



        
