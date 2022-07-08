#include "irods/authentication_plugin_framework.hpp"

#include <irods/authCheck.h>
#include <irods/authPluginRequest.h>
#include <irods/authRequest.h>
#include <irods/authResponse.h>
#include <irods/authenticate.h>
#include <irods/genQuery.h>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_auth_constants.hpp>
#include <irods/irods_auth_plugin.hpp>
#include <irods/irods_client_server_negotiation.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_error.hpp>
#include <irods/irods_krb_object.hpp>
#include <irods/irods_kvp_string_parser.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/irods_server_properties.hpp>
#include <irods/irods_stacktrace.hpp>
#include <irods/miscServerFunct.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/rodsLog.h>

#ifdef RODS_SERVER
#include <irods/rsGenQuery.hpp>
#include <irods/rsAuthCheck.hpp>
#include <irods/rsAuthResponse.hpp>
#include <irods/rsAuthRequest.hpp>
#endif // RODS_SERVER

#include <gssapi.h>
#include <openssl/md5.h>

#include <string>

static const int ikrbDebugFlag = 0;
static const gss_OID gss_nt_service_name_krb = 0;
static const unsigned int SCRATCH_BUFFER_SIZE = 20000;
static char ikrbScratchBuffer[SCRATCH_BUFFER_SIZE];
static int ikrbTokenHeaderMode = 1;  /* 1 is the normal mode,
                                        0 means running in a non-token-header mode, ie Java; dynamically cleared. */

#ifdef RODS_SERVER
// =-=-=-=-=-=-=-
// NOTE:: this needs to become a property
// Set requireServerAuth to 1 to fail authentications from
// un-authenticated Servers (for example, if the LocalZoneSID
// is not set)
//static const int requireServerAuth = 0;
static int krbAuthReqStatus = 0;
static int krbAuthReqError = 0;
static const int krbAuthErrorSize = 1000;
static char krbAuthReqErrorMsg[krbAuthErrorSize];
#endif


static rError_t *ikrb_rErrorPtr;

// static gss_cred_id_t myCreds = GSS_C_NO_CREDENTIAL;
static const int MAX_FDS = 32;
static gss_ctx_id_t context[MAX_FDS] = {
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT,
    GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT, GSS_C_NO_CONTEXT
};

static unsigned int context_flags;

static gss_cred_id_t my_creds = GSS_C_NO_CREDENTIAL;

namespace
{
    using json = nlohmann::json;
    using log_auth = irods::experimental::log::authentication;
    namespace irods_auth = irods::experimental::auth;

    void krb_log_error_1(rError_t& _r_error,
                         const char *callerMsg,
                         OM_uint32 code,
                         int type,
                         bool is_client)
    {
        OM_uint32 minorStatus;
        gss_buffer_desc msg;
        unsigned int msg_ctx;
        int status;
        std::string whichSide;

        if ( is_client ) {
            whichSide = "Client side:";
        }
        else {
            whichSide = "On iRODS-Server side:";
        }

        msg_ctx = 0;
        status = KRB_ERROR_FROM_KRB_LIBRARY;
        do {
            gss_display_status( &minorStatus, code, type, GSS_C_NULL_OID, &msg_ctx, &msg );
            rodsLogAndErrorMsg( LOG_ERROR, &_r_error, status,
                                "%sGSS-API error %s: %s", whichSide.c_str(), callerMsg,
                                ( char * ) msg.value );
            ( void ) gss_release_buffer( &minorStatus, &msg );
        }
        while ( msg_ctx );
    } // krb_log_error_1

    void krb_log_error(rError_t& _r_error,
                       const char *msg,
                       OM_uint32 majorStatus,
                       OM_uint32 minorStatus,
                       bool is_client)
    {
        krb_log_error_1( _r_error, msg, majorStatus, GSS_C_GSS_CODE, is_client );
        krb_log_error_1( _r_error, msg, minorStatus, GSS_C_MECH_CODE, is_client );
    } // krb_log_error

    std::string krb_setup_creds(rError_t& _r_error,
                                bool _is_client,
                                const std::string& _specified_name)
    {
        OM_uint32 majorStatus, minorStatus;
        gss_name_t myName = GSS_C_NO_NAME;
        gss_name_t myName2 = GSS_C_NO_NAME;

        // generate a gss name struct for the specified name
        if (!_specified_name.empty()) {
            gss_buffer_desc name_buf{};
            name_buf.value = strdup(_specified_name.c_str());
            name_buf.length = _specified_name.length() + 1;
            majorStatus = gss_import_name(&minorStatus,
                                          &name_buf,
                                          const_cast<gss_OID>(gss_nt_service_name_krb),
                                          &myName);
            if (majorStatus != GSS_S_COMPLETE) {
                const std::string msg = fmt::format(fmt::runtime(
                                                    "Failed importing specified name: \"{}\"."),
                                                    _specified_name);

                krb_log_error(_r_error, msg.data(), majorStatus, minorStatus, _is_client);

                THROW(KRB_ERROR_IMPORT_NAME, msg);
            }
        }

        // Acquire the credentials if we do not have any yet
        if (my_creds == GSS_C_NO_CREDENTIAL) {
            majorStatus = gss_acquire_cred(
                    &minorStatus,
                    myName,
                    0,
                    GSS_C_NULL_OID_SET,
                    _specified_name.empty() ? GSS_C_INITIATE : GSS_C_ACCEPT,
                    &my_creds,
                    NULL,
                    NULL);
        }
        else {
            // Already have credentials so all is well
            majorStatus = GSS_S_COMPLETE;
        }

        if (majorStatus != GSS_S_COMPLETE) {
            static const char* msg = "Failed acquiring credentials.";
            krb_log_error(_r_error, msg, majorStatus, minorStatus, _is_client);
            THROW(KRB_ERROR_ACQUIRING_CREDS, msg);
        }

        // set the credentials in the auth object
        gss_release_name(&minorStatus, &myName);

        majorStatus = gss_inquire_cred(&minorStatus, my_creds, &myName2, NULL, NULL, NULL);
        if (majorStatus != GSS_S_COMPLETE) {
            static const char* msg = "Failed inquiring creds for the name.";
            krb_log_error(_r_error, msg, majorStatus, minorStatus, _is_client);
            THROW(KRB_ERROR_ACQUIRING_CREDS, msg);
        }

        gss_OID doid2;
        gss_buffer_desc client_name2;
        majorStatus = gss_display_name(&minorStatus, myName2, &client_name2, &doid2);
        if (majorStatus != GSS_S_COMPLETE) {
            static const char* msg = "Failed during displaying name.";
            krb_log_error(_r_error, msg, majorStatus, minorStatus, _is_client);
            THROW(KRB_ERROR_DISPLAYING_NAME, msg);
        }

        std::string display_name;
        if (client_name2.value && client_name2.length > 0) {
            display_name = static_cast<char*>(client_name2.value);
        }

        majorStatus = gss_release_name(&minorStatus, &myName2);
        if (majorStatus != GSS_S_COMPLETE) {
            static const char* msg = "Failed to release cred name.";
            krb_log_error(_r_error, msg, majorStatus, minorStatus, _is_client);
            THROW(KRB_ERROR_RELEASING_NAME, msg);
        }

        // TODO: should this be released?
        gss_release_buffer(&minorStatus, &client_name2);

        return display_name;
    } // krb_setup_creds

    /// @brief Import the specified name into a KRB name
    void krb_import_name(rError_t& _r_error,
                         const char* _service_name,
                         gss_name_t* _output_name,
                         bool _is_client)
    {
        *_output_name = GSS_C_NO_NAME;

        const std::size_t size = _service_name ? std::strlen(_service_name) + 1 : 0;

        if (0 == size) {
            return;
        }

        gss_buffer_desc name_buffer{};
        name_buffer.value = static_cast<void*>(const_cast<char*>(_service_name));
        name_buffer.length = size;

        OM_uint32 minor_status;
        OM_uint32 major_status = gss_import_name(&minor_status,
                                                 &name_buffer,
                                                 const_cast<gss_OID>(gss_nt_service_name_krb),
                                                 _output_name);

        if (major_status != GSS_S_COMPLETE) {
            /* could use "if (GSS_ERROR(majorStatus))" but I believe it should
               always be GSS_S_COMPLETE if successful  */
            static const char* msg = "Failed importing name.";
            krb_log_error(_r_error, msg, major_status, minor_status, _is_client);
            THROW(KRB_ERROR_IMPORT_NAME, msg);
        }
    } // krb_import_name

    /// @brief Write a KRB buffer.
    /**
       Write a buffer to the network, continuing with subsequent writes if
       the write system call returns with only some of it sent.
    */
    irods::error krb_write_all(int fd,
                               char *buf,
                               unsigned int nbyte,
                               unsigned int* _rtn_bytes_written)
    {
        int ret;
        char *ptr;

        for ( ptr = buf; nbyte; ptr += ret, nbyte -= ret ) {
            ret = write( fd, ptr, nbyte );
            if (ret < 0 || errno == EINTR) {
                return ERROR(ret, fmt::format(fmt::runtime(
                            "Error writing the krb buffer, error = {}."),
                            strerror(errno)));
            }

            if ( ret == 0 ) {
                *_rtn_bytes_written = ptr - buf;
            }
            else if ( errno == EINTR ) {
                continue;
            }
        }

        if ( ikrbDebugFlag > 0 ) {
            fprintf( stderr, "_ikrbWriteAll, wrote=%ld\n", ptr - buf );
        }
        *_rtn_bytes_written = ( ptr - buf );

        return SUCCESS();
    } // krb_write_all

    /// @brief Send a KRB token
    /**
       Send a token (which is a buffer and a length); write the token length (as a network long) and then the token data on the file
       descriptor.  It returns 0 on success, and -1 if an error occurs or if it could not write all the data.
    */
    irods::error krb_send_token(gss_buffer_desc* _send_tok, int _fd)
    {
        unsigned int bytes_written;

        if ( ikrbTokenHeaderMode ) {
            int len = htonl( _send_tok->length );

            char* cp = ( char * ) &len;
            // Apparent hack to handle len variables of greater than 4 bytes. Should be safe since token lengths should likely never
            // be greater than 4 billion but adding a check here to be sure
            if ( sizeof( len ) > 4 ) {
                if (( ( len << ( ( sizeof( len ) - 4 ) * 8 ) ) >> ( ( sizeof( len ) - 4 ) * 8 ) ) != len) {
                    return ERROR(KRB_ERROR_SENDING_TOKEN_LENGTH, "Token length has significant bits past 4 bytes.");
                }

                cp += sizeof( len ) - 4;
            }

            if (const auto err = krb_write_all(_fd, cp, 4, &bytes_written); !err.ok()) {
                return PASSMSG("Error sending KRB token length.", err);
            }

            if (bytes_written != 4) {
                const auto ec = KRB_ERROR_SENDING_TOKEN_LENGTH;
                rodsLogAndErrorMsg(LOG_ERROR, ikrb_rErrorPtr, ec,
                        "sending token data: %d of %d bytes written",
                        bytes_written, _send_tok->length);
                return ERROR(ec, fmt::format(fmt::runtime(
                            "Error sending token data: {} of {} bytes written."),
                            bytes_written, _send_tok->length));
            }
        }

        const auto ret = krb_write_all(_fd, (char*)_send_tok->value, _send_tok->length, &bytes_written);
        if (!ret.ok()) {
            return PASSMSG("Error sending token data2.", ret);
        }

        if (bytes_written != _send_tok->length) {
            const auto ec = KRB_ERROR_SENDING_TOKEN_LENGTH;
            rodsLogAndErrorMsg(LOG_ERROR, ikrb_rErrorPtr, ec,
                    "sending token data2: %u of %u bytes written",
                    bytes_written, _send_tok->length);
            return ERROR(ec, fmt::format(fmt::runtime(
                        "Sending token data2: {} of {} bytes written."),
                        bytes_written, _send_tok->length));
        }

        return ret;
    } // krb_send_token

    /// @brief Read into a buffer continuing to read until full
    irods::error krb_read_all(int _fd,
                              char* _buf,
                              unsigned int _nbyte,
                              unsigned int* _rtn_bytes_read)
    {
        int ret = 1;
        char *ptr;

        for ( ptr = _buf; ret != 0 && _nbyte; ptr += ret, _nbyte -= ret ) {
            ret = read( _fd, ptr, _nbyte );
            if (ret < 0 && errno == EINTR) {
                return ERROR(KRB_SOCKET_READ_ERROR, "Failed reading KRB buffer.");
            }
        }

        *_rtn_bytes_read = ptr - _buf;

        return SUCCESS();
    } // krb_read_all

    /// @brief Read the KRB token header
    irods::error krb_rcv_token_header(int _fd, unsigned int* _rtn_length)
    {
        int length;
        char *cp;
        unsigned int bytes_read;

        length = 0;
        cp = ( char * ) &length;
        if ( sizeof( length ) > 4 ) {
            cp += sizeof( length ) - 4;
        }
        if (const auto err = krb_read_all(_fd, cp, 4, &bytes_read); !err.ok()) {
            return PASSMSG("Failed reading KRB token header.", err);
        }

        if (bytes_read != 4 && bytes_read != 0) {
            const auto ec = KRB_ERROR_READING_TOKEN_LENGTH;
            rodsLogAndErrorMsg(LOG_ERROR, ikrb_rErrorPtr, ec,
                    "reading token length: %d of %d bytes read", bytes_read, 4);
            return ERROR(ec, fmt::format(fmt::runtime(
                        "Error reading KRB token, length {} of {} bytes read."),
                        bytes_read, 4));
        }

        length = ntohl( length );

        if ( ikrbDebugFlag > 0 ) {
            fprintf( stderr, "token length = %d\n", length );
        }

        *_rtn_length = length;

        return SUCCESS();
    } // krb_rcv_token_header

    /// @brief Read a KRB token body
    irods::error krb_rcv_token_body(int _fd,
                                    gss_buffer_t _token,
                                    unsigned int _length,
                                    unsigned int* _rtn_bytes_read)
    {
        unsigned int bytes_read;

        if (_token->length < _length) {
            const auto ec = KRB_ERROR_TOKEN_TOO_LARGE;
            const std::string msg = fmt::format(fmt::runtime(
                    "[%s] error, token is too large for buffer, %d bytes in token, buffer is %d bytes"),
                    __func__, _length, _token->length);
            rodsLogAndErrorMsg(LOG_ERROR, ikrb_rErrorPtr, ec, msg.c_str());
            return ERROR(ec, msg);
        }

        if (!_token->value) {
            return ERROR(KRB_ERROR_BAD_TOKEN_RCVED, "Error KRB token buffer has NULL value.");
        }

        _token->length = _length;

        if (const auto err = krb_read_all(_fd, (char*)_token->value, _token->length, &bytes_read); !err.ok()) {
            return PASSMSG("Error reading KRB token body.", err);
        }

        if (bytes_read != _token->length) {
            const auto ec = KRB_PARTIAL_TOKEN_READ;
            const std::string msg = fmt::format(fmt::runtime(
                    "Error reading token data, {} of {} bytes read."),
                    bytes_read, _token->length);
            rodsLogAndErrorMsg(LOG_ERROR, ikrb_rErrorPtr, ec, msg.c_str());
            return ERROR(ec, msg);
        }

        *_rtn_bytes_read = _token->length;

        return SUCCESS();
    } // krb_rcv_token_body

    ///@brief Receive a KRB token
    irods::error krb_receive_token(int _fd, gss_buffer_t _token, unsigned int* _rtn_bytes_read)
    {
        int tmpLength;
        char* cp;
        int i;

        if ( ikrbTokenHeaderMode ) {

            /*
              First, if in normal mode, peek to see if the other side is sending
              headers and possibly switch into non-header mode.
            */
            tmpLength = 0;
            cp = ( char * ) &tmpLength;
            if ( sizeof( tmpLength ) > 4 ) {
                cp += sizeof( tmpLength ) - 4;
            }
            i = recv( _fd, cp, 4, MSG_PEEK );
            tmpLength = ntohl( tmpLength );
            if ( ikrbDebugFlag > 0 ) {
                fprintf( stderr, "peek length = %d\n", tmpLength );
            }
            if ( tmpLength > 100000 ) {
                ikrbTokenHeaderMode = 0;
                if ( ikrbDebugFlag > 0 ) {
                    fprintf( stderr, "switching to non-hdr mode\n" );
                }
            }
        }

        if ( ikrbTokenHeaderMode ) {
            unsigned int length;
            if (const auto err = krb_rcv_token_header(_fd, &length); !err.ok()) {
                return PASSMSG("Failed reading KRB header.", err);
            }

            if (const auto err = krb_rcv_token_body(_fd, _token, length, _rtn_bytes_read); !err.ok()) {
                return PASSMSG("Failed reading KRB body.", err);
            }
        }
        else {
            i = read( _fd, ( char * ) _token->value, _token->length );
            if ( ikrbDebugFlag > 0 ) {
                fprintf( stderr, "rcved token, length = %d\n", i );
            }

            if (i < 0) {
                return ERROR(i, "Failed to read KRB token.");
            }

            _token->length = i;        /* Assume all of token is rcv'ed */
        }
        return SUCCESS();
    } // krb_receive_token
} // anonymous namespace

namespace irods
{
    class kerberos_authentication : public irods_auth::authentication_base {
    public:
        kerberos_authentication()
        {
            add_operation(AUTH_CLIENT_AUTH_REQUEST,  OPERATION(rcComm_t, kerberos_auth_client_request));
            add_operation(AUTH_ESTABLISH_CONTEXT,    OPERATION(rcComm_t, kerberos_auth_establish_context));
            add_operation(AUTH_CLIENT_AUTH_RESPONSE, OPERATION(rcComm_t, kerberos_auth_client_response));
#ifdef RODS_SERVER
            add_operation(AUTH_AGENT_AUTH_REQUEST,   OPERATION(rsComm_t, kerberos_auth_agent_request));
            add_operation(AUTH_AGENT_AUTH_RESPONSE,  OPERATION(rsComm_t, kerberos_auth_agent_response));
#endif
        } // ctor

    private:
        json auth_client_start(rcComm_t& comm, const json& req)
        {
            json resp{req};
            resp["user_name"] = comm.proxyUser.userName;
            resp["zone_name"] = comm.proxyUser.rodsZone;
            resp[irods_auth::next_operation] = AUTH_CLIENT_AUTH_REQUEST;

            return resp;
        } // auth_client_start

        json kerberos_auth_client_request(rcComm_t& comm, const json& req)
        {
            // Setup the credentials
            const auto service_name = krb_setup_creds(*comm.rError, true, "");

            json svr_req{req};
            svr_req[irods::AUTH_USER_KEY] = service_name;
            svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_REQUEST;

            auto resp = irods_auth::request(comm, svr_req);

            irods_auth::throw_if_request_message_is_missing_key(
                resp, {"request_result"}
            );

            const auto result = resp.at("request_result").get_ref<const std::string&>();
            // TODO: request_result contains the service name? Is that the password??
            if (const auto ec = obfSavePw(0, 0, 0, result.data()); ec < 0) {
                THROW(ec, fmt::format(
                      "failed to save obfuscated password while authenticating user [{}]",
                      service_name));
            }

            resp[irods_auth::next_operation] = AUTH_ESTABLISH_CONTEXT;

            return resp;
        } // kerberos_auth_client_request

        json kerberos_auth_establish_context(rcComm_t& _comm, const json& req)
        {
            irods_auth::throw_if_request_message_is_missing_key(
                req, {"request_result"}
            );

            json resp{req};

            ikrb_rErrorPtr = _comm.rError;

            std::string service_principal;
            if (const char* p = getenv("irodsServerDn"); p) {
                service_principal = p;
            }
            else if (const char* p = getenv("SERVER_DN"); p) {
                service_principal = p;
            }
            else {
                service_principal = req.at("request_result").get<std::string>();
            }

            gss_name_t target_name;

            const auto release_target_name = irods::at_scope_exit{
                [&target_name, &service_principal] {
                    if (!service_principal.empty()) {
                        // TODO: should we be checking status/returncode?
                        OM_uint32 status;
                        gss_release_name(&status, &target_name);
                    }
                }
            };

            krb_import_name(*ikrb_rErrorPtr, service_principal.data(), &target_name, true);

            // Perform the context-establishment loop.
            //
            // On each pass through the loop, tokenPtr points to the token
            // to send to the server (or GSS_C_NO_BUFFER on the first pass).
            // Every generated token is stored in send_tok which is then
            // transmitted to the server; every received token is stored in
            // recv_tok, which tokenPtr is then set to, to be processed by
            // the next call to gss_init_sec_context.
            //
            // GSS-API guarantees that send_tok's length will be non-zero
            // if and only if the server is expecting another token from us,
            // and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
            // and only if the server has another token to send us.

            const int fd = _comm.sock;
            gss_OID oid = GSS_C_NULL_OID;
            gss_buffer_desc send_tok{};
            gss_buffer_desc recv_tok{};
            gss_buffer_desc* tokenPtr = GSS_C_NO_BUFFER;

            context[fd] = GSS_C_NO_CONTEXT;

            OM_uint32 majorStatus, minorStatus;
            OM_uint32 flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

            do {
                majorStatus = gss_init_sec_context( &minorStatus,
                        my_creds, &context[fd], target_name, oid,
                        flags, 0,
                        NULL,           /* no channel bindings */
                        tokenPtr, NULL, /* ignore mech type */
                        &send_tok, &context_flags,
                        NULL); /* ignore time_rec */

                /* since recv_tok is not malloc'ed, don't need to call
                   gss_release_buffer, instead clear it. */
                std::memset( ikrbScratchBuffer, 0, SCRATCH_BUFFER_SIZE );

                if (majorStatus != GSS_S_COMPLETE && majorStatus != GSS_S_CONTINUE_NEEDED) {
                    constexpr bool is_client = true;
                    const std::string msg = fmt::format(fmt::runtime(
                                "Failed initializing KRB context. Major status: {}\tMinor status: {}"),
                                majorStatus, minorStatus);
                    krb_log_error(*_comm.rError, msg.data(), majorStatus, minorStatus, is_client);
                    majorStatus = gss_release_name(&minorStatus, &target_name);
                    if (majorStatus != GSS_S_COMPLETE) {
                        static const char* release_msg = "Error releasing name.";
                        krb_log_error(*_comm.rError, release_msg, majorStatus, minorStatus, is_client);
                    }
                    THROW(KRB_ERROR_INIT_SECURITY_CONTEXT, msg);
                }

                if (send_tok.length != 0) {
                    if (const auto err = krb_send_token( &send_tok, fd ); !err.ok()) {
                        // TODO: should we be checking these release calls?
                        gss_release_buffer(&minorStatus, &send_tok);
                        gss_release_name(&minorStatus, &target_name);
                        THROW(err.code(), err.result());
                    }
                }

                gss_release_buffer(&minorStatus, &send_tok);

                if (majorStatus == GSS_S_CONTINUE_NEEDED) {
                    recv_tok.value = &ikrbScratchBuffer;
                    recv_tok.length = SCRATCH_BUFFER_SIZE;
                    unsigned int bytes_read;
                    if (const auto ret = krb_receive_token(fd, &recv_tok, &bytes_read); !ret.ok()) {
                        gss_release_name( &minorStatus, &target_name );
                        const auto err = PASSMSG("Error reading KRB token.", ret);
                        THROW(err.code(), err.result());
                    }

                    tokenPtr = &recv_tok;
                }
            }
            while (majorStatus == GSS_S_CONTINUE_NEEDED);

            resp[irods_auth::next_operation] = AUTH_CLIENT_AUTH_RESPONSE;

            return resp;
        } // kerberos_auth_establish_context

        json kerberos_auth_client_response(rcComm_t& comm, const json& req)
        {
            irods_auth::throw_if_request_message_is_missing_key(
                req, {"user_name", "zone_name"}
            );

            json svr_req{req};
            svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
            auto resp = irods_auth::request(comm, svr_req);

            comm.loggedIn = 1;

            resp[irods_auth::next_operation] = irods_auth::flow_complete;

            return resp;
        } // kerberos_auth_client_response

#ifdef RODS_SERVER
        json kerberos_auth_agent_request(rsComm_t& comm, const json& req)
        {
            if (krbAuthReqStatus == 1) {
                krbAuthReqStatus = 0;
                if (krbAuthReqError != 0) {
                    rodsLogAndErrorMsg(LOG_NOTICE, &comm.rError, krbAuthReqError, krbAuthReqErrorMsg);
                    THROW(krbAuthReqError, "A KRB auth request error has occurred.");
                }
            }

            const auto kerberos_name = irods::get_server_property<std::string>("KerberosServicePrincipal");

            constexpr bool client = false;
            const auto service_name = krb_setup_creds(comm.rError, client, kerberos_name);

            comm.gsiRequest = 1;
            if (comm.auth_scheme) {
                free(comm.auth_scheme);
            }
            comm.auth_scheme = strdup(irods::AUTH_KRB_SCHEME.c_str());

            json resp{req};
            resp["request_result"] = service_name;
            return resp;
        } // kerberos_auth_agent_request

        json kerberos_auth_agent_response(rsComm_t& comm, const json& req)
        {
            irods_auth::throw_if_request_message_is_missing_key(
                req, {"user_name", "zone_name"}
            );

            // need to do NoLogin because it could get into inf loop for cross zone auth
            rodsServerHost_t *rodsServerHost;
            auto zone_name = req.at("zone_name").get<std::string>();
            int status = getAndConnRcatHostNoLogin(&comm, PRIMARY_RCAT, const_cast<char*>(zone_name.c_str()), &rodsServerHost);
            if ( status < 0 ) {
                THROW(status, "Connecting to rcat host failed.");
            }

            authCheckInp_t authCheckInp{};
            authCheckInp.challenge = _rsAuthRequestGetChallenge();

            const std::string username = fmt::format("{}#{}", req.at("user_name").get<std::string>(), zone_name);
            authCheckInp.username = const_cast<char*>(username.data());

            // build the response string
            irods::kvp_map_t kvp;
            kvp[irods::AUTH_SCHEME_KEY] = irods::AUTH_KRB_SCHEME;
            const std::string resp_str = irods::kvp_string(kvp);
            char response[RESPONSE_LEN + 2]{};
            std::strncpy(response, resp_str.c_str(), RESPONSE_LEN + 2);

            authCheckInp.response = response;

            authCheckOut_t* authCheckOut = nullptr;
            if (LOCAL_HOST == rodsServerHost->localFlag) {
                status = rsAuthCheck(&comm, &authCheckInp, &authCheckOut);
            }
            else {
                status = rcAuthCheck(rodsServerHost->conn, &authCheckInp, &authCheckOut);
                /* not likely we need this connection again */
                rcDisconnect(rodsServerHost->conn);
                rodsServerHost->conn = nullptr;
            }

            if (status < 0 || !authCheckOut) {
                THROW(status, "rcAuthCheck failed.");
            }

            json resp{req};

            // Do we need to consider remote zones here?
            if (LOCAL_HOST != rodsServerHost->localFlag) {
                if (!authCheckOut->serverResponse) {
                    log_auth::info("Warning, cannot authenticate remote server, no serverResponse field");
                    THROW(REMOTE_SERVER_AUTH_NOT_PROVIDED, "Authentication disallowed. no serverResponse field.");
                }

                if (*authCheckOut->serverResponse == '\0') {
                    log_auth::info("Warning, cannot authenticate remote server, serverResponse field is empty");
                    THROW(REMOTE_SERVER_AUTH_EMPTY, "Authentication disallowed, empty serverResponse.");
                }

                char md5Buf[CHALLENGE_LEN + MAX_PASSWORD_LEN + 2]{};
                strncpy(md5Buf, authCheckInp.challenge, CHALLENGE_LEN);

                char userZone[NAME_LEN + 2]{};
                strncpy(userZone, req.at("zone_name").get<std::string>().data(), NAME_LEN + 1);

                char serverId[MAX_PASSWORD_LEN + 2]{};
                getZoneServerId(userZone, serverId);

                if ('\0' == serverId[0]) {
                    log_auth::info("rsAuthResponse: Warning, cannot authenticate the remote server, no RemoteZoneSID defined in server_config.json");
                    THROW(REMOTE_SERVER_SID_NOT_DEFINED, "Authentication disallowed, no RemoteZoneSID defined");
                }

                strncpy(md5Buf + CHALLENGE_LEN, serverId, strlen(serverId));

                char digest[RESPONSE_LEN + 2]{};
                obfMakeOneWayHash(
                    HASH_TYPE_DEFAULT,
                    ( unsigned char* )md5Buf,
                    CHALLENGE_LEN + MAX_PASSWORD_LEN,
                    ( unsigned char* )digest );

                for (int i = 0; i < RESPONSE_LEN; i++) {
                    if (digest[i] == '\0') {
                        digest[i]++;
                    }  /* make sure 'string' doesn't end early*/
                }

                char* cp = authCheckOut->serverResponse;

                for (int i = 0; i < RESPONSE_LEN; i++) {
                    if ( *cp++ != digest[i] ) {
                        THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, "Authentication disallowed, server response incorrect.");
                    }
                }
            }

            /* Set the clientUser zone if it is null. */
            if ('\0' == comm.clientUser.rodsZone[0]) {
                zoneInfo_t* tmpZoneInfo{};
                status = getLocalZoneInfo( &tmpZoneInfo );
                if ( status < 0 ) {
                    THROW(status, "getLocalZoneInfo failed.");
                }
                else {
                    strncpy(comm.clientUser.rodsZone, tmpZoneInfo->zoneName, NAME_LEN);
                }
            }

            /* have to modify privLevel if the icat is a foreign icat because
             * a local user in a foreign zone is not a local user in this zone
             * and vice versa for a remote user
             */
            if (rodsServerHost->rcatEnabled == REMOTE_ICAT ) {
                /* proxy is easy because rodsServerHost is based on proxy user */
                if ( authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH ) {
                    authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                }
                else if ( authCheckOut->privLevel == LOCAL_USER_AUTH ) {
                    authCheckOut->privLevel = REMOTE_USER_AUTH;
                }

                /* adjust client user */
                if ( 0 == strcmp(comm.proxyUser.userName, comm.clientUser.userName ) ) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }
                else {
                    zoneInfo_t *tmpZoneInfo;
                    status = getLocalZoneInfo( &tmpZoneInfo );
                    if ( status < 0 ) {
                        THROW(status, "getLocalZoneInfo failed.");
                    }
                    else {
                        if ( 0 == strcmp( tmpZoneInfo->zoneName, comm.clientUser.rodsZone ) ) {
                            /* client is from local zone */
                            if ( REMOTE_PRIV_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                            }
                            else if ( REMOTE_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                            }
                        }
                        else {
                            /* client is from remote zone */
                            if ( LOCAL_PRIV_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                            else if ( LOCAL_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                        }
                    }
                }
            }
            else if ( 0 == strcmp(comm.proxyUser.userName,  comm.clientUser.userName ) ) {
                authCheckOut->clientPrivLevel = authCheckOut->privLevel;
            }

            irods::throw_on_insufficient_privilege_for_proxy_user(comm, authCheckOut->privLevel);

            log_auth::debug(
                    "rsAuthResponse set proxy authFlag to {}, client authFlag to {}, user:{} proxy:{} client:{}",
                    authCheckOut->privLevel,
                    authCheckOut->clientPrivLevel,
                    authCheckInp.username,
                    comm.proxyUser.userName,
                    comm.clientUser.userName);

            if ( strcmp(comm.proxyUser.userName, comm.clientUser.userName ) != 0 ) {
                comm.proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                comm.clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
            }
            else {          /* proxyUser and clientUser are the same */
                comm.proxyUser.authInfo.authFlag =
                    comm.clientUser.authInfo.authFlag = authCheckOut->privLevel;
            }

            if ( authCheckOut != NULL ) {
                if ( authCheckOut->serverResponse != NULL ) {
                    free( authCheckOut->serverResponse );
                }
                free( authCheckOut );
            }

            return resp;
        } // kerberos_auth_agent_response
#endif // RODS_SERVER
    }; // class kerberos_authentication
} // namespace irods

extern "C"
irods::kerberos_authentication* plugin_factory(const std::string&, const std::string&)
{
    return new irods::kerberos_authentication{};
}

