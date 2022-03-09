#include <irods/authCheck.h>
#include <irods/authPluginRequest.h>
#include <irods/authRequest.h>
#include <irods/authResponse.h>
#include <irods/authenticate.h>
#include <irods/genQuery.h>
#include <irods/irods_auth_constants.hpp>
#include <irods/irods_auth_plugin.hpp>
#include <irods/irods_client_server_negotiation.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_error.hpp>
#include <irods/irods_krb_object.hpp>
#include <irods/irods_kvp_string_parser.hpp>
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
#endif


#include <openssl/md5.h>
#include <gssapi.h>
#include <string>


static const int ikrbDebugFlag = 0;
static const int gss_nt_service_name_krb = 0;
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
static const int requireServerAuth = 0;
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

irods::error krb_kerberos_name(std::string& kerberos_name) {
    try {
        kerberos_name = irods::get_server_property<std::string>("KerberosServicePrincipal");
    } catch (const irods::exception& e) {
        return irods::error(e);
    }
    return SUCCESS();
}

static gss_cred_id_t my_creds = GSS_C_NO_CREDENTIAL;

void krb_print_token(
    gss_buffer_t tok ) {
    unsigned int i, j;
    unsigned char *p = ( unsigned char * )tok->value;
    fprintf( stderr, "%s, length=%lu\n", __FUNCTION__, tok->length );
    j = 0;
    for ( i = 0; i < tok->length; i++, p++ ) {
        if ( i < 16 || i > tok->length - 16 ) {
            fprintf( stderr, "%02x ", *p );
            if ( i == 15 || i == ( tok->length - 1 ) ) {
                fprintf( stderr, "\n" );
            }
        }
        else {
            j++;
            if ( j < 4 ) {
                fprintf( stderr, "." );
            }
            if ( j == 4 ) {
                fprintf( stderr, "\n" );
            }
        }
    }
    fprintf( stderr, "\n" );
    fflush( stderr );
}

void krb_log_error_1(
    rError_t* _r_error,
    const char *callerMsg,
    OM_uint32 code,
    int type,
    bool is_client ) {
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
        rodsLogAndErrorMsg( LOG_ERROR, _r_error, status,
                            "%sGSS-API error %s: %s", whichSide.c_str(), callerMsg,
                            ( char * ) msg.value );
        ( void ) gss_release_buffer( &minorStatus, &msg );
    }
    while ( msg_ctx );
}

void krb_log_error(
    rError_t* _r_error,
    const char *msg,
    OM_uint32 majorStatus,
    OM_uint32 minorStatus,
    bool is_client ) {
    krb_log_error_1( _r_error, msg, majorStatus, GSS_C_GSS_CODE, is_client );
    krb_log_error_1( _r_error, msg, minorStatus, GSS_C_MECH_CODE, is_client );
}

irods::error krb_no_op(irods::krb_auth_object_ptr) {
    return SUCCESS();
}

irods::error krb_setup_creds(
    irods::krb_auth_object_ptr _go,
    bool _is_client,
    const std::string& _specified_name,
    std::string& _rtn_name ) {
    irods::error result = SUCCESS();
    gss_buffer_desc name_buf;
    OM_uint32 majorStatus, minorStatus;
    gss_name_t myName = GSS_C_NO_NAME;
    gss_name_t myName2 = GSS_C_NO_NAME;
    gss_buffer_desc client_name2;
    gss_OID doid2;

    // generate a gss name struct for the specified name
    if ( !_specified_name.empty() ) {
        name_buf.value = strdup( _specified_name.c_str() );
        name_buf.length = _specified_name.length() + 1;
        majorStatus = gss_import_name( &minorStatus, &name_buf, ( gss_OID )gss_nt_service_name_krb, &myName );
        if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_IMPORT_NAME, "Failed importing specified name: \"%s\".",
                                       _specified_name.c_str() ) ).ok() ) {
            krb_log_error( _go->r_error(), "Importing specified name.", majorStatus, minorStatus, _is_client );
        }
    }
    if ( result.ok() ) {
        // Acquire the credentials if we do not have any yet
        // gss_cred_id_t tmp_creds = GSS_C_NO_CREDENTIAL;
        if ( my_creds == GSS_C_NO_CREDENTIAL ) {
            if ( _specified_name.empty() ) {
                majorStatus = gss_acquire_cred( &minorStatus, myName, 0, GSS_C_NULL_OID_SET, GSS_C_INITIATE, &my_creds, NULL, NULL );
            }
            else {
                majorStatus = gss_acquire_cred( &minorStatus, myName, 0, GSS_C_NULL_OID_SET, GSS_C_ACCEPT, &my_creds, NULL, NULL );
            }
        }
        else {
            // Already have credentials so all is well
            majorStatus = GSS_S_COMPLETE;
        }
        if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_ACQUIRING_CREDS, "Failed acquiring credentials." ) ).ok() ) {
            krb_log_error( _go->r_error(), "Acquiring credentials.", majorStatus, minorStatus, _is_client );
        }
        else {

            // set the credentials in the auth object
            _go->creds( my_creds );
            gss_release_name( &minorStatus, &myName );

            majorStatus = gss_inquire_cred( &minorStatus, _go->creds(), &myName2, NULL, NULL, NULL );
            if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_ACQUIRING_CREDS, "Failed inquiring creds for the name." ) ).ok() ) {
                krb_log_error( _go->r_error(), "Inquiring credentials", majorStatus, minorStatus, _is_client );
            }
            else {
                majorStatus = gss_display_name( &minorStatus, myName2, &client_name2, &doid2 );
                if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_DISPLAYING_NAME, "Failed during displaying name." ) ).ok() ) {
                    krb_log_error( _go->r_error(), "Display name", majorStatus, minorStatus, _is_client );
                }
                else {
                    if ( client_name2.value != NULL && client_name2.length > 0 ) {
                        _rtn_name = std::string( ( char* )client_name2.value );
                        _go->service_name( ( char* )client_name2.value );
                    }
                    majorStatus = gss_release_name( &minorStatus, &myName2 );
                    if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_RELEASING_NAME, "Failed to release cred name." ) ).ok() ) {
                        krb_log_error( _go->r_error(), "Releasing name", majorStatus, minorStatus, _is_client );
                    }
                    gss_release_buffer( &minorStatus, &client_name2 );
                }
            }
        }
    }
    return result;
}

/// @brief no op
irods::error krb_auth_success_stub( void ) {
    irods::error result = SUCCESS();
    return result;
}

/// @brief Import the specified name into a KRB name
irods::error krb_import_name(
    rError_t* _r_error,        // For error reporting
    const char* _service_name, // KRB service name
    gss_name_t* _target_name,  // KRB target name
    bool _is_client ) {
    irods::error result = SUCCESS();
    gss_buffer_desc name_buffer;

    *_target_name = GSS_C_NO_NAME;
    if ( _service_name != NULL && strlen( _service_name ) > 0 ) {
        size_t size = strlen( _service_name ) + 1;
        name_buffer.value = malloc( size );
        memcpy( name_buffer.value, _service_name, size );
        name_buffer.length = size;

        OM_uint32 minor_status;
        OM_uint32 major_status = gss_import_name( &minor_status, &name_buffer, ( gss_OID ) gss_nt_service_name_krb, _target_name );

        if ( !( result = ASSERT_ERROR( major_status == GSS_S_COMPLETE, KRB_ERROR_IMPORT_NAME, "Failed importing name." ) ).ok() ) {
            /* could use "if (GSS_ERROR(majorStatus))" but I believe it should
               always be GSS_S_COMPLETE if successful  */
            krb_log_error( _r_error, "importing name", major_status, minor_status, _is_client );
        }
    }
    return result;
}

/// @brief Write a KRB buffer.
/**
   Write a buffer to the network, continuing with subsequent writes if
   the write system call returns with only some of it sent.
*/
irods::error krb_write_all(
    int fd,
    char *buf,
    unsigned int nbyte,
    unsigned int* _rtn_bytes_written ) {
    irods::error result = SUCCESS();
    int ret;
    char *ptr;

    for ( ptr = buf; result.ok() && nbyte; ptr += ret, nbyte -= ret ) {
        ret = write( fd, ptr, nbyte );
        if ( ( result = ASSERT_ERROR( ret >= 0 && errno != EINTR, ret, "Error writing the krb buffer, error = %s.", strerror( errno ) ) ).ok() ) {
            if ( ret == 0 ) {
                *_rtn_bytes_written = ptr - buf;
            }
            else if ( errno == EINTR ) {
                continue;
            }
        }
    }
    if ( result.ok() ) {
        if ( ikrbDebugFlag > 0 ) {
            fprintf( stderr, "_ikrbWriteAll, wrote=%ld\n", ptr - buf );
        }
        *_rtn_bytes_written = ( ptr - buf );
    }

    return result;
}

/// @brief Send a KRB token
/**
   Send a token (which is a buffer and a length); write the token length (as a network long) and then the token data on the file
   descriptor.  It returns 0 on success, and -1 if an error occurs or if it could not write all the data.
*/
irods::error krb_send_token(
    gss_buffer_desc* _send_tok,
    int _fd ) {
    irods::error result = SUCCESS();
    irods::error ret;
    int len;
    char *cp;
    unsigned int bytes_written;

    if ( ikrbTokenHeaderMode ) {
        len = htonl( _send_tok->length );

        cp = ( char * ) &len;
        // Apparent hack to handle len variables of greater than 4 bytes. Should be safe since token lengths should likely never
        // be greater than 4 billion but adding a check here to be sure
        if ( sizeof( len ) > 4 ) {
            if ( ( result = ASSERT_ERROR( ( ( len << ( ( sizeof( len ) - 4 ) * 8 ) ) >> ( ( sizeof( len ) - 4 ) * 8 ) ) == len,
                                          KRB_ERROR_SENDING_TOKEN_LENGTH, "Token length has significant bits past 4 bytes." ) ).ok() ) {
                cp += sizeof( len ) - 4;
            }
        }
        if ( result.ok() ) {
            ret = krb_write_all( _fd, cp, 4, &bytes_written );
            if ( ( result = ASSERT_PASS( ret, "Error sending KRB token length." ) ).ok() ) {
                if ( !( result = ASSERT_ERROR( bytes_written == 4, KRB_ERROR_SENDING_TOKEN_LENGTH, "Error sending token data: %u of %u bytes written.",
                                               bytes_written, _send_tok->length ) ).ok() ) {
                    rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, result.code(), "sending token data: %d of %d bytes written",
                                        bytes_written, _send_tok->length );
                }
            }
        }
    }

    if ( result.ok() ) {
        ret = krb_write_all( _fd, ( char * )_send_tok->value, _send_tok->length, &bytes_written );
        if ( ( result = ASSERT_PASS( ret, "Error sending token data2." ) ).ok() ) {

            if ( !( result = ASSERT_ERROR( bytes_written == _send_tok->length, KRB_ERROR_SENDING_TOKEN_LENGTH,
                                           "Sending token data2: %u of %u bytes written.", bytes_written, _send_tok->length ) ).ok() ) {
                rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, result.code(), "sending token data2: %u of %u bytes written",
                                    bytes_written, _send_tok->length );
            }
        }
    }

    return result;
}

/// @brief Read into a buffer continuing to read until full
static irods::error krb_read_all(
    int _fd,
    char* _buf,
    unsigned int _nbyte,
    unsigned int* _rtn_bytes_read ) {
    irods::error result = SUCCESS();
    int ret = 1;
    char *ptr;

    for ( ptr = _buf; result.ok() && ret != 0 && _nbyte; ptr += ret, _nbyte -= ret ) {
        ret = read( _fd, ptr, _nbyte );
        result = ASSERT_ERROR( ret >= 0 || errno != EINTR, KRB_SOCKET_READ_ERROR, "Failed reading KRB buffer." );
    }

    if ( result.ok() ) {
        *_rtn_bytes_read = ptr - _buf;
    }

    return result;
}

/// @brief Read the KRB token header
irods::error krb_rcv_token_header(
    int _fd,
    unsigned int* _rtn_length ) {
    irods::error result = SUCCESS();
    irods::error ret;
    int length;
    char *cp;
    int status;
    unsigned int bytes_read;

    length = 0;
    cp = ( char * ) &length;
    if ( sizeof( length ) > 4 ) {
        cp += sizeof( length ) - 4;
    }
    ret = krb_read_all( _fd, cp, 4, &bytes_read );
    if ( ( result = ASSERT_PASS( ret, "Failed reading KRB token header." ) ).ok() ) {
        if ( !( result = ASSERT_ERROR( bytes_read == 4 || bytes_read == 0, KRB_ERROR_READING_TOKEN_LENGTH,
                                       "Error reading KRB token, length %u of %u bytes read.", bytes_read, 4 ) ).ok() ) {
            status = KRB_ERROR_READING_TOKEN_LENGTH;
            rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, status, "reading token length: %d of %d bytes read", bytes_read, 4 );
        }
        else {
            length = ntohl( length );

            if ( ikrbDebugFlag > 0 ) {
                fprintf( stderr, "token length = %d\n", length );
            }

            *_rtn_length = length;
        }
    }

    return result;
}

/// @brief Read a KRB token body
irods::error krb_rcv_token_body(
    int _fd,
    gss_buffer_t _token,
    unsigned int _length,
    unsigned int* _rtn_bytes_read ) {
    irods::error result = SUCCESS();
    irods::error ret;
    unsigned int bytes_read;
    int status;

    if ( !( result = ASSERT_ERROR( _token->length >= _length, KRB_ERROR_TOKEN_TOO_LARGE,
                                   "Error KRB token is too large for buffer, %u bytes in token, buffer is %d bytes.",
                                   _length, _token->length ) ).ok() ) {
        status = KRB_ERROR_TOKEN_TOO_LARGE;
        rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, status,
                            "_ikrbRcvTokenBody error, token is too large for buffer, %d bytes in token, buffer is %d bytes",
                            _length, _token->length );
    }
    else {
        if ( ( result = ASSERT_ERROR( _token->value != NULL, KRB_ERROR_BAD_TOKEN_RCVED, "Error KRB token buffer has NULL value." ) ).ok() ) {

            _token->length = _length;

            ret = krb_read_all( _fd, ( char * ) _token->value, _token->length, &bytes_read );
            if ( ( result = ASSERT_PASS( ret, "Error reading KRB token body." ) ).ok() ) {
                if ( !( result = ASSERT_ERROR( bytes_read == _token->length, KRB_PARTIAL_TOKEN_READ, "Error reading token data, %u of %d bytes read.",
                                               bytes_read, _token->length ) ).ok() ) {
                    status = KRB_PARTIAL_TOKEN_READ;
                    rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, status,
                                        "reading token data: %d of %d bytes read\n",
                                        bytes_read, _token->length );
                }
                else {
                    *_rtn_bytes_read = _token->length;
                }
            }
        }
    }

    return result;
}

///@brief Receive a KRB token
irods::error krb_receive_token(
    int _fd,
    gss_buffer_t _token,
    unsigned int* _rtn_bytes_read ) {
    irods::error result = SUCCESS();
    irods::error ret;

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
        ret = krb_rcv_token_header( _fd, &length );
        if ( ( result = ASSERT_PASS( ret, "Failed reading KRB header." ) ).ok() ) {
            ret = krb_rcv_token_body( _fd, _token, length, _rtn_bytes_read );
            result = ASSERT_PASS( ret, "Failed reading KRB body." );
        }
    }
    else {

        i = read( _fd, ( char * ) _token->value, _token->length );
        if ( ikrbDebugFlag > 0 ) {
            fprintf( stderr, "rcved token, length = %d\n", i );
        }
        if ( ( result = ASSERT_ERROR( i > 0, i, "Failed to read KRB token." ) ).ok() ) {
            _token->length = i;        /* Assume all of token is rcv'ed */
        }
    }
    return result;
}

/// @brief Print the current context flags
void krb_display_ctx_flags() {
    if ( context_flags & GSS_C_DELEG_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_DELEG_FLAG\n" );
    }
    if ( context_flags & GSS_C_MUTUAL_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_MUTUAL_FLAG\n" );
    }
    if ( context_flags & GSS_C_REPLAY_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_REPLAY_FLAG\n" );
    }
    if ( context_flags & GSS_C_SEQUENCE_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_SEQUENCE_FLAG\n" );
    }
    if ( context_flags & GSS_C_CONF_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_CONF_FLAG \n" );
    }
    if ( context_flags & GSS_C_INTEG_FLAG ) {
        fprintf( stdout, "context flag: GSS_C_INTEG_FLAG \n" );
    }
}

std::string get_kerberos_service_principal(const irods::krb_auth_object& object) {
    if (const char *irodsServerDn = getenv("irodsServerDn")) {
        return irodsServerDn;
    }

    if (const char *SERVER_DN = getenv("SERVER_DN")) {
        return SERVER_DN;
    }

    return object.request_result();
}


/// @brief Establish context - take the auth request results and massage them for the auth response call
irods::error krb_auth_establish_context(
    irods::plugin_context& _ctx ) {
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {

        irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object>( _ctx.fco() );

        int fd;

        fd = ptr->sock();

        ikrb_rErrorPtr = ptr->r_error();

        gss_OID oid = GSS_C_NULL_OID;
        gss_buffer_desc send_tok, recv_tok, *tokenPtr = NULL;
        gss_name_t target_name;
        OM_uint32 majorStatus, minorStatus;
        OM_uint32 flags = 0;

        // overload the use of the username in the response structure
        std::string serverName = get_kerberos_service_principal(*ptr);
        ret = krb_import_name( ikrb_rErrorPtr, serverName.c_str(), &target_name, true );
        if ( ( result = ASSERT_PASS( ret, "Failed to import service name into KRB." ) ).ok() ) {

            /*
             * Perform the context-establishment loop.
             *
             * On each pass through the loop, tokenPtr points to the token
             * to send to the server (or GSS_C_NO_BUFFER on the first pass).
             * Every generated token is stored in send_tok which is then
             * transmitted to the server; every received token is stored in
             * recv_tok, which tokenPtr is then set to, to be processed by
             * the next call to gss_init_sec_context.
             *
             * GSS-API guarantees that send_tok's length will be non-zero
             * if and only if the server is expecting another token from us,
             * and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
             * and only if the server has another token to send us.
             */

            tokenPtr = GSS_C_NO_BUFFER;
            context[fd] = GSS_C_NO_CONTEXT;
            flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
            do {
                majorStatus = gss_init_sec_context( &minorStatus,
                                                    my_creds, &context[fd], target_name, oid,
                                                    flags, 0,
                                                    NULL,           /* no channel bindings */
                                                    tokenPtr, NULL, /* ignore mech type */
                                                    &send_tok, &context_flags,
                                                    NULL ); /* ignore time_rec */

                /* since recv_tok is not malloc'ed, don't need to call
                   gss_release_buffer, instead clear it. */
                memset( ikrbScratchBuffer, 0, SCRATCH_BUFFER_SIZE );

                if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE || majorStatus == GSS_S_CONTINUE_NEEDED,
                                               KRB_ERROR_INIT_SECURITY_CONTEXT,
                                               "Failed initializing KRB context. Major status: %d\tMinor status: %d" ) ).ok() ) {
                    krb_log_error( ptr->r_error(), "initializing context", majorStatus, minorStatus, true );
                    ( void ) gss_release_name( &minorStatus, &target_name );
                }
                else {

                    if ( send_tok.length != 0 ) {
                        ret = krb_send_token( &send_tok, fd );
                        if ( !( result = ASSERT_PASS( ret, "Failed sending KRB token." ) ).ok() ) {
                            ( void ) gss_release_buffer( &minorStatus, &send_tok );
                            ( void ) gss_release_name( &minorStatus, &target_name );
                        }
                    }

                    if ( result.ok() ) {

                        ( void ) gss_release_buffer( &minorStatus, &send_tok );

                        if ( majorStatus == GSS_S_CONTINUE_NEEDED ) {
                            recv_tok.value = &ikrbScratchBuffer;
                            recv_tok.length = SCRATCH_BUFFER_SIZE;
                            unsigned int bytes_read;
                            ret = krb_receive_token( fd, &recv_tok, &bytes_read );
                            if ( !( result = ASSERT_PASS( ret, "Error reading KRB token." ) ).ok() ) {
                                ( void ) gss_release_name( &minorStatus, &target_name );
                            }
                            else {
                                tokenPtr = &recv_tok;
                            }
                        }
                    }
                }
            }
            while ( result.ok() && majorStatus == GSS_S_CONTINUE_NEEDED );

            if (!serverName.empty()) {
                ( void ) gss_release_name( &minorStatus, &target_name );
            }

            if ( ikrbDebugFlag > 0 ) {
                krb_display_ctx_flags();
            }
        }
    }
    return result;
}

/// @brief Setup auth object with relevant information
irods::error krb_auth_client_start(
    irods::plugin_context& _ctx,
    rcComm_t* _comm,
    const char*) {
    irods::error result = SUCCESS();
    irods::error ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context" ) ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm != NULL, SYS_INVALID_INPUT_PARAM, "Null rcComm_t pointer." ) ).ok() ) {

            irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object>( _ctx.fco() );

            // set the user name from the conn
            ptr->user_name( _comm->proxyUser.userName );

            // set the zone name from the conn
            ptr->zone_name( _comm->proxyUser.rodsZone );

            // set the socket from the conn
            ptr->sock( _comm->sock );
        }
    }

    return result;
}

/**
   Set up an session between this server and a connected new client.

   Establishses a GSS-API context (as the service specified in
   ikrbSetupCreds) with an incoming client, and returns the
   authenticated client name (the id on the other side of the socket).
   The other side (the client) must call ikrbEstablishContextClientside at
   about the same time for the exchanges across the network to work
   (each side will block waiting for the other).

   If successful, the context handle is set in the global context array.
   If unsuccessful, an error message is displayed and -1 is returned.

**/
irods::error krb_establish_context_serverside(
    irods::plugin_context& _ctx,
    rsComm_t* _comm,
    char* _clientName,
    int _maxLen_clientName ) {
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {

        irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object>( _ctx.fco() );

        int fd;

        fd = _comm->sock;
        ikrb_rErrorPtr = &_comm->rError;

        gss_buffer_desc send_buffer, recv_buffer;
        gss_buffer_desc client_name;
        gss_name_t client;
        gss_OID doid;
        OM_uint32 majorStatus, minorStatus, tmp_status;

        int i, j;

#if defined(IKRB_TIMING)
        struct timeval startTimeFunc, endTimeFunc, sTimeDiff;
        float fSec;
        /* Starting timer for function */
        ( void ) gettimeofday( &startTimeFunc, ( struct timezone * ) 0 );

#endif

        context[fd] = GSS_C_NO_CONTEXT;

        recv_buffer.value = &ikrbScratchBuffer;

        do {
            recv_buffer.length = SCRATCH_BUFFER_SIZE;
            unsigned int bytes_read;
            ret = krb_receive_token( fd, &recv_buffer, &bytes_read );
            if ( !( result = ASSERT_PASS( ret, "Failed reading KRB token." ) ).ok() ) {
                rodsLogAndErrorMsg( LOG_ERROR, ikrb_rErrorPtr, result.code(),
                                    "ikrbEstablishContextServerside" );
            }
            else {
                if ( ikrbDebugFlag > 0 ) {
                    fprintf( stderr, "Received token (size=%lu): \n",
                             recv_buffer.length );
                    krb_print_token( &recv_buffer );
                }

                majorStatus = gss_accept_sec_context( &minorStatus,
                                                      &context[fd], my_creds, &recv_buffer,
                                                      GSS_C_NO_CHANNEL_BINDINGS, &client, &doid,
                                                      &send_buffer, &context_flags,
                                                      NULL,     /* ignore time_rec */
                                                      NULL );   /* ignore del_cred_handle */

                gss_buffer_desc name_buffer;
                gss_OID tmp_oid;
                gss_display_name( &tmp_status, client, &name_buffer, &tmp_oid );

                if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE || majorStatus == GSS_S_CONTINUE_NEEDED,
                                               KRB_ACCEPT_SEC_CONTEXT_ERROR, "Error accepting KRB security context for client: \"%s\".",
                                               ( char* )name_buffer.value ) ).ok() ) {
                    krb_log_error( &_comm->rError, "accepting context", majorStatus, minorStatus, false );
                    memset( ikrbScratchBuffer, 0, SCRATCH_BUFFER_SIZE );
                }
                else {

                    /* since buffer is not malloc'ed, don't need to call
                       gss_release_buffer, instead clear it. */
                    memset( ikrbScratchBuffer, 0, SCRATCH_BUFFER_SIZE );

                    if ( send_buffer.length != 0 ) {
                        if ( ikrbDebugFlag > 0 ) {
                            fprintf( stderr, "Sending accept_sec_context token (size=%lu):\n", send_buffer.length );
                            krb_print_token( &send_buffer );
                        }
                        ret = krb_send_token( &send_buffer, fd );
                        result = ASSERT_PASS( ret, "Failed sending KRB token." );
                    }
                    if ( ikrbDebugFlag > 0 ) {
                        if ( majorStatus == GSS_S_CONTINUE_NEEDED ) {
                            fprintf( stderr, "continue needed...\n" );
                        }
                    }
                }
            }
        }
        while ( result.ok() && majorStatus == GSS_S_CONTINUE_NEEDED );

        if ( result.ok() ) {

            /* convert name (internally represented) to a string */
            majorStatus = gss_display_name( &minorStatus, client, &client_name, &doid );
            if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_DISPLAYING_NAME, "Failed displaying name: \"%s\"",
                                           client_name ) ).ok() ) {
                krb_log_error( &_comm->rError, "displaying name", majorStatus, minorStatus, false );
            }
            else {

                i = client_name.length;
                if ( _maxLen_clientName < i ) {
                    i = _maxLen_clientName;
                }

                strncpy( _clientName, ( char* )client_name.value, i );
                j = client_name.length;
                if ( _maxLen_clientName > j ) {
                    _clientName[client_name.length] = '\0';
                }

                /* release the name structure */
                majorStatus = gss_release_name( &minorStatus, &client );

                if ( !( result = ASSERT_ERROR( majorStatus == GSS_S_COMPLETE, KRB_ERROR_RELEASING_NAME, "Error releasing name." ) ).ok() ) {
                    krb_log_error( &_comm->rError, "releasing name", majorStatus, minorStatus, false );
                }
                else {
                    ( void ) gss_release_buffer( &minorStatus, &client_name );

#if defined(IKRB_TIMING)
                    ( void ) gettimeofday( &endTimeFunc, ( struct timezone * ) 0 );
                    ( void ) _ikrbTime( &sTimeDiff, &endTimeFunc, &startTimeFunc );
                    fSec =
                        ( float ) sTimeDiff.tv_sec + ( ( float ) sTimeDiff.tv_usec / 1000000.0 );

                    /* for IKRB_TIMING  print time */
                    fprintf( stdout, " ---  %.5f sec time taken for executing "
                             "ikrbEstablishContextServerside() ---  \n", fSec );
#endif
                }
            }
        }
    }

    return result;

}


#ifdef RODS_SERVER
/// @brief Setup auth object with relevant information
irods::error krb_auth_agent_start(
    irods::plugin_context& _ctx,
    const char*) {
    irods::error result = SUCCESS();
    irods::error ret;

    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context" ) ).ok() ) {
        irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object>( _ctx.fco() );
        int status;
        char clientName[500];
        genQueryInp_t genQueryInp;
        genQueryOut_t *genQueryOut;
        char condition1[MAX_NAME_LEN];
        char condition2[MAX_NAME_LEN];
        char *tResult;
        int privLevel;
        int clientPrivLevel;
        int noNameMode;

        krbAuthReqStatus = 1;

        ret = krb_establish_context_serverside( _ctx, _ctx.comm(), clientName, 500 );
        if ( ( result = ASSERT_PASS( ret, "Failed to establish server side context." ) ).ok() ) {

            memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

            noNameMode = 0;
            if ( strlen( _ctx.comm()->clientUser.userName ) > 0 ) {
                /* regular mode */

                snprintf( condition1, MAX_NAME_LEN, "='%s'", clientName );
                addInxVal( &genQueryInp.sqlCondInp, COL_USER_DN, condition1 );

                snprintf( condition2, MAX_NAME_LEN, "='%s'",
                          _ctx.comm()->clientUser.userName );
                addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, condition2 );

                addInxIval( &genQueryInp.selectInp, COL_USER_ID, 1 );
                addInxIval( &genQueryInp.selectInp, COL_USER_TYPE, 1 );
                addInxIval( &genQueryInp.selectInp, COL_USER_ZONE, 1 );

                genQueryInp.maxRows = 2;

                status = rsGenQuery( _ctx.comm(), &genQueryInp, &genQueryOut );
            }
            else {
                /*
                  The client isn't providing the rodsUserName so query on just
                  the DN.  If it returns just one row, set the clientUser to
                  the returned irods user name.
                */
                noNameMode = 1;
                memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

                snprintf( condition1, MAX_NAME_LEN, "='%s'", clientName );
                addInxVal( &genQueryInp.sqlCondInp, COL_USER_DN, condition1 );

                addInxIval( &genQueryInp.selectInp, COL_USER_ID, 1 );
                addInxIval( &genQueryInp.selectInp, COL_USER_TYPE, 1 );
                addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
                addInxIval( &genQueryInp.selectInp, COL_USER_ZONE, 1 );

                genQueryInp.maxRows = 2;

                status = rsGenQuery( _ctx.comm(), &genQueryInp, &genQueryOut );

                if ( status == CAT_NO_ROWS_FOUND ) { /* not found */
                    /* execute the rule acGetUserByDN.  By default this
                       is a no-op but at some sites can be configured to
                       run a process to determine a user by DN (for VO support)
                       or possibly create the user.
                       The stdout of the process is the irodsUserName to use.

                       The corresponding rule would be something like this:
                       acGetUserByDN(*arg,*OUT)||msiExecCmd(t,"*arg",null,null,null,*OUT)|nop
                    */
                    ruleExecInfo_t rei;
                    const char *args[2];
                    msParamArray_t myInOutParamArray;

                    memset( ( char* )&rei, 0, sizeof( rei ) );
                    rei.rsComm = _ctx.comm();
                    rei.uoic = &_ctx.comm()->clientUser;
                    rei.uoip = &_ctx.comm()->proxyUser;
                    args[0] = clientName;
                    char out[200] = "*cmdOutput";
                    args[1] = out;

                    rei.inOutMsParamArray = myInOutParamArray;

                    applyRuleArg( "acGetUserByDN", args, 2, &rei, NO_SAVE_REI );


                    /* Try the query again, whether or not the rule succeeded, to see
                       if the user has been added. */
                    memset( &genQueryInp, 0, sizeof( genQueryInp_t ) );

                    snprintf( condition1, MAX_NAME_LEN, "='%s'", clientName );
                    addInxVal( &genQueryInp.sqlCondInp, COL_USER_DN, condition1 );

                    addInxIval( &genQueryInp.selectInp, COL_USER_ID, 1 );
                    addInxIval( &genQueryInp.selectInp, COL_USER_TYPE, 1 );
                    addInxIval( &genQueryInp.selectInp, COL_USER_NAME, 1 );
                    addInxIval( &genQueryInp.selectInp, COL_USER_ZONE, 1 );

                    genQueryInp.maxRows = 2;

                    status = rsGenQuery( _ctx.comm(), &genQueryInp, &genQueryOut );
                }
                if ( status == 0 ) {
                    char *myBuf;
                    strncpy( _ctx.comm()->clientUser.userName, genQueryOut->sqlResult[2].value,
                             NAME_LEN );
                    strncpy( _ctx.comm()->proxyUser.userName, genQueryOut->sqlResult[2].value,
                             NAME_LEN );
                    strncpy( _ctx.comm()->clientUser.rodsZone, genQueryOut->sqlResult[3].value,
                             NAME_LEN );
                    strncpy( _ctx.comm()->proxyUser.rodsZone, genQueryOut->sqlResult[3].value,
                             NAME_LEN );
                    myBuf = ( char * )malloc( NAME_LEN * 2 );
                    snprintf( myBuf, NAME_LEN * 2, "%s=%s", SP_CLIENT_USER,
                              _ctx.comm()->clientUser.userName );
                    putenv( myBuf );
                    free( myBuf ); // JMC cppcheck - leak
                }
            }
            if ( !( result = ASSERT_ERROR( status != CAT_NO_ROWS_FOUND && genQueryOut != NULL, KRB_USER_DN_NOT_FOUND,
                                           "DN mismatch, user=%s, Certificate DN+%s, status = %d.", _ctx.comm()->clientUser.userName,
                                           clientName, status ) ).ok() ) {
                rodsLog( LOG_NOTICE,
                         "ikrbServersideAuth: DN mismatch, user=%s, Certificate DN=%s, status=%d",
                         _ctx.comm()->clientUser.userName,
                         clientName,
                         status );
                snprintf( krbAuthReqErrorMsg, sizeof krbAuthReqErrorMsg,
                          "ikrbServersideAuth: DN mismatch, user=%s, Certificate DN=%s, status=%d",
                          _ctx.comm()->clientUser.userName,
                          clientName,
                          status );
                krbAuthReqError = status;
            }

            else if ( !( result = ASSERT_ERROR( status >= 0, status, "rsGenQuery failed, status = %d.", status ) ).ok() ) {
                rodsLog( LOG_NOTICE,
                         "ikrbServersideAuth: rsGenQuery failed, status = %d", status );
                snprintf( krbAuthReqErrorMsg, sizeof krbAuthReqErrorMsg,
                          "ikrbServersideAuth: rsGenQuery failed, status = %d", status );
                krbAuthReqError = status;
            }

            else {

                if ( noNameMode == 0 ) {
                    if ( !( result = ASSERT_ERROR( genQueryOut != NULL && genQueryOut->rowCnt >= 1, KRB_USER_DN_NOT_FOUND,
                                                   "No matching user DN found." ) ).ok() ) {
                        krbAuthReqError = KRB_USER_DN_NOT_FOUND;
                    }
                    else if ( !( result = ASSERT_ERROR( genQueryOut->rowCnt == 1, KRB_NAME_MATCHES_MULTIPLE_USERS,
                                                        "Multiple matching user DN's found." ) ).ok() ) {
                        krbAuthReqError = KRB_NAME_MATCHES_MULTIPLE_USERS;
                    }
                    else if ( !( result = ASSERT_ERROR( genQueryOut->attriCnt == 3, KRB_QUERY_INTERNAL_ERROR,
                                                        "Wrong number of values returned from query: %u, expected 3.",
                                                        genQueryOut->attriCnt ) ).ok() ) {
                        krbAuthReqError = KRB_QUERY_INTERNAL_ERROR;
                    }
                }
                else {
                    if ( !( result = ASSERT_ERROR( genQueryOut != NULL && genQueryOut->rowCnt >= 1, KRB_USER_DN_NOT_FOUND,
                                                   "No matching user DN found." ) ).ok() ) {
                        krbAuthReqError = KRB_USER_DN_NOT_FOUND;
                    }
                    else if ( !( result = ASSERT_ERROR( genQueryOut->rowCnt == 1, KRB_NAME_MATCHES_MULTIPLE_USERS,
                                                        "Multiple matching user DN's found." ) ).ok() ) {
                        krbAuthReqError = KRB_NAME_MATCHES_MULTIPLE_USERS;
                    }
                    else if ( !( result = ASSERT_ERROR( genQueryOut->attriCnt == 4, KRB_QUERY_INTERNAL_ERROR,
                                                        "Wrong number of values returned from query: %u, expected 4.",
                                                        genQueryOut->attriCnt ) ).ok() ) {
                        krbAuthReqError = KRB_QUERY_INTERNAL_ERROR;
                    }
                }

                // trap errors that have occurred
                if ( result.ok() ) {
                    tResult = genQueryOut->sqlResult[0].value;
                    tResult = genQueryOut->sqlResult[1].value;
                    privLevel = LOCAL_USER_AUTH;
                    clientPrivLevel = LOCAL_USER_AUTH;

                    if ( strcmp( tResult, "rodsadmin" ) == 0 ) {
                        privLevel = LOCAL_PRIV_USER_AUTH;
                        clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                    }

                    status = chkProxyUserPriv( _ctx.comm(), privLevel );
                    if ( ( result = ASSERT_ERROR( status >= 0, status, "Failed checking proxy user priviledges." ) ).ok() ) {

                        _ctx.comm()->proxyUser.authInfo.authFlag = privLevel;
                        _ctx.comm()->clientUser.authInfo.authFlag = clientPrivLevel;

                        // Reset the auth scheme here so we do not try to authenticate again unless the client requests it.
                        if ( _ctx.comm()->auth_scheme != NULL ) {
                            free( _ctx.comm()->auth_scheme );
                        }
                        _ctx.comm()->auth_scheme = NULL;

                        if ( noNameMode ) { /* We didn't before, but now have an irodsUserName */
                            int status2, status3;
                            rodsServerHost_t *rodsServerHost = NULL;
                            status2 = getAndConnRcatHost( _ctx.comm(), MASTER_RCAT,
                                                          _ctx.comm()->myEnv.rodsZone, &rodsServerHost );
                            if ( status2 >= 0 &&
                                 rodsServerHost->localFlag == REMOTE_HOST &&
                                 rodsServerHost->conn != NULL ) {  /* If the IES is remote */

                                status3 = rcDisconnect( rodsServerHost->conn ); /* disconnect*/

                                /* And clear out the connection information so
                                   getAndConnRcatHost will reconnect.  This may leak some
                                   memory but only happens at most once in an agent:  */
                                rodsServerHost->conn = NULL;

                                /* And reconnect (with irodsUserName here and in the IES): */
                                status3 = getAndConnRcatHost( _ctx.comm(), MASTER_RCAT,
                                                              _ctx.comm()->myEnv.rodsZone,
                                                              &rodsServerHost );
                                if ( !( result = ASSERT_ERROR( status3 == 0, status3,
                                                               "KRB server side auth failed in connecting to Rcat host, status = %d.",
                                                               status3 ) ).ok() ) {
                                    rodsLog( LOG_ERROR,
                                             "ikrbServersideAuth failed in getAndConnRcatHost, status = %d",
                                             status3 );
                                }
                            }
                        }

                    } // if ((result = ASSERT_ERROR(status >= 0, status, "Failed checking proxy user priviledges." )).ok())
                } // if(result.ok())
            } // if ((result = ASSERT_ERROR(status >= 0, status, "rsGenQuery failed, status = %d.", status )).ok())
        } // if((result = ASSERT_PASS(ret, "Failed to establish server side context.")).ok())
    } // if ( ( result = ASSERT_PASS( ret, "Invalid plugin context" ) ).ok() )

    return result;
}
#endif

irods::error krb_auth_client_request(
    irods::plugin_context& _ctx,
    rcComm_t* _comm ) {
    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid< irods::krb_auth_object >();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {

        // =-=-=-=-=-=-=-
        // get the auth object
        irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast <irods::krb_auth_object > ( _ctx.fco() );

        // Setup the credentials
        std::string service_name;
        ret = krb_setup_creds( ptr, true, std::string(), service_name );
        if ( ( result = ASSERT_PASS( ret, "Failed to setup KRB credentials." ) ).ok() ) {
            ptr->service_name( service_name );

            // =-=-=-=-=-=-=-
            // get the context string
            std::string context = ptr->context( );

            // =-=-=-=-=-=-=-
            // append the auth scheme and user name
            context += irods::kvp_delimiter() + irods::AUTH_USER_KEY + irods::kvp_association() + ptr->user_name();

            // =-=-=-=-=-=-=-
            // error check string size against MAX_NAME_LEN
            if ( ( result = ASSERT_ERROR( context.size() <= MAX_NAME_LEN, SYS_INVALID_INPUT_PARAM, "context string > max name len" ) ).ok() ) {

                // =-=-=-=-=-=-=-
                // copy the context to the req in struct
                authPluginReqInp_t req_in;
                strncpy( req_in.context_, context.c_str(), context.size() + 1 );

                // =-=-=-=-=-=-=-
                // copy the auth scheme to the req in struct
                strncpy( req_in.auth_scheme_, irods::AUTH_KRB_SCHEME.c_str(), irods::AUTH_KRB_SCHEME.size() + 1 );

                // =-=-=-=-=-=-=-
                // make the call to our auth request
                authPluginReqOut_t* req_out = 0;
                int status = rcAuthPluginRequest( _comm, &req_in, &req_out );

                // =-=-=-=-=-=-=-
                // handle errors and exit
                if ( ( result = ASSERT_ERROR( status >= 0, status, "call to rcAuthRequest failed." ) ).ok() ) {

                    // =-=-=-=-=-=-=-
                    // copy over the resulting irods kerberos service name
                    // and cache the result in our auth object
                    ptr->request_result( req_out->result_ );
                    status = obfSavePw( 0, 0, 0, req_out->result_ );
                    free( req_out );
                }
            }
        }
    }
    return result;
}

#ifdef RODS_SERVER
irods::error krb_auth_agent_request(
    irods::plugin_context& _ctx ) {

    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {

        if ( krbAuthReqStatus == 1 ) {
            krbAuthReqStatus = 0;
            if ( !( result = ASSERT_ERROR( krbAuthReqError == 0, krbAuthReqError,
                                           "A KRB auth request error has occurred." ) ).ok() ) {
                rodsLogAndErrorMsg( LOG_NOTICE, &_ctx.comm()->rError, krbAuthReqError,
                                    krbAuthReqErrorMsg );
            }
        }

        if ( result.ok() ) {
            irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object>( _ctx.fco() );
            std::string kerberos_name;
            ret = krb_kerberos_name(kerberos_name);
            if ( ( result = ASSERT_PASS( ret, "Failed to fetch Kerberos name from server config." ) ).ok() ) {
                std::string service_name;
                ret = krb_setup_creds( ptr, false, kerberos_name, service_name );
                if ( ( result = ASSERT_PASS( ret, "Setting up KRB credentials failed." ) ).ok() ) {
                    _ctx.comm()->gsiRequest = 1;
                    if ( _ctx.comm()->auth_scheme != NULL ) {
                        free( _ctx.comm()->auth_scheme );
                    }
                    _ctx.comm()->auth_scheme = strdup( irods::AUTH_KRB_SCHEME.c_str() );
                    ptr->service_name( service_name );
                    ptr->request_result( service_name );
                }
            }
        }
    }
    return result;
}
#endif

irods::error krb_auth_client_response(
    irods::plugin_context& _ctx,
    rcComm_t* _comm ) {
    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
        if ( ( result = ASSERT_ERROR( _comm, SYS_INVALID_INPUT_PARAM, "Null comm pointer." ) ).ok() ) {

            // =-=-=-=-=-=-=-
            // get the auth object
            irods::krb_auth_object_ptr ptr = boost::dynamic_pointer_cast<irods::krb_auth_object >( _ctx.fco() );

            irods::kvp_map_t kvp;
            kvp[irods::AUTH_SCHEME_KEY] = irods::AUTH_KRB_SCHEME;
            std::string resp_str = irods::kvp_string( kvp );

            // =-=-=-=-=-=-=-
            // build the response string
            char response[ RESPONSE_LEN + 2 ];
            strncpy( response, resp_str.c_str(), RESPONSE_LEN + 2 );

            // =-=-=-=-=-=-=-
            // build the username#zonename string
            std::string user_name = ptr->user_name() + "#" + ptr->zone_name();
            char username[ MAX_NAME_LEN ];
            strncpy( username, user_name.c_str(), MAX_NAME_LEN );

            authResponseInp_t auth_response;
            auth_response.response = response;
            auth_response.username = username;
            int status = rcAuthResponse( _comm, &auth_response );
            result = ASSERT_ERROR( status >= 0, status, "Call to rcAuthResponseFailed." );
        }
    }

    return result;
}

#ifdef RODS_SERVER
static irods::error check_proxy_user_privileges(
    rsComm_t *rsComm,
    int proxyUserPriv ) {
    irods::error result = SUCCESS();

    if ( strcmp( rsComm->proxyUser.userName, rsComm->clientUser.userName ) != 0 ) {

        /* remote privileged user can only do things on behalf of users from
         * the same zone */
        result = ASSERT_ERROR( proxyUserPriv >= LOCAL_PRIV_USER_AUTH ||
                               ( proxyUserPriv >= REMOTE_PRIV_USER_AUTH &&
                                 strcmp( rsComm->proxyUser.rodsZone, rsComm->clientUser.rodsZone ) == 0 ),
                               SYS_PROXYUSER_NO_PRIV,
                               "Proxyuser: \"%s\" with %d no priv to auth clientUser: \"%s\".",
                               rsComm->proxyUser.userName, proxyUserPriv, rsComm->clientUser.userName );
    }

    return result;
}

irods::error krb_auth_agent_response(
    irods::plugin_context& _ctx,
    authResponseInp_t*          _resp ) {
    irods::error result = SUCCESS();
    irods::error ret;

    // validate incoming parameters
    ret = _ctx.valid<irods::krb_auth_object>();
    if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
        int status;
        char *bufp;
        authCheckInp_t authCheckInp;
        authCheckOut_t *authCheckOut = NULL;
        rodsServerHost_t *rodsServerHost;

        char digest[RESPONSE_LEN + 2];
        char md5Buf[CHALLENGE_LEN + MAX_PASSWORD_LEN + 2];
        char serverId[MAX_PASSWORD_LEN + 2];
        MD5_CTX context;

        bufp = _rsAuthRequestGetChallenge();

        /* need to do NoLogin because it could get into inf loop for cross
         * zone auth */

        status = getAndConnRcatHostNoLogin( _ctx.comm(), MASTER_RCAT,
                                            _ctx.comm()->proxyUser.rodsZone, &rodsServerHost );
        if ( ( result = ASSERT_ERROR( status >= 0, status, "Connecting to rcat host failed." ) ).ok() ) {

            memset( &authCheckInp, 0, sizeof( authCheckInp ) );
            authCheckInp.challenge = bufp;
            authCheckInp.response = _resp->response;
            authCheckInp.username = _resp->username;

            if ( rodsServerHost->localFlag == LOCAL_HOST ) {
                status = rsAuthCheck( _ctx.comm(), &authCheckInp, &authCheckOut );
            }
            else {
                status = rcAuthCheck( rodsServerHost->conn, &authCheckInp, &authCheckOut );
                /* not likely we need this connection again */
                rcDisconnect( rodsServerHost->conn );
                rodsServerHost->conn = NULL;
            }
            if ( ( result = ASSERT_ERROR( status >= 0 && authCheckOut != NULL, status, "rcAuthCheck failed, status = %d.",
                                          status ) ).ok() ) { // JMC cppcheck

                if ( rodsServerHost->localFlag != LOCAL_HOST ) {
                    if ( authCheckOut->serverResponse == NULL ) {
                        rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, no serverResponse field" );
                        result = ASSERT_ERROR( !requireServerAuth, REMOTE_SERVER_AUTH_NOT_PROVIDED, "Authentication disallowed. no serverResponse field." );
                    }

                    else {
                        char *cp;
                        int OK, len, i;
                        if ( *authCheckOut->serverResponse == '\0' ) {
                            rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, serverResponse field is empty" );
                            result = ASSERT_ERROR( !requireServerAuth, REMOTE_SERVER_AUTH_EMPTY, "Authentication disallowed, empty serverResponse." );
                        }
                        else {
                            char username2[NAME_LEN + 2];
                            char userZone[NAME_LEN + 2];
                            memset( md5Buf, 0, sizeof( md5Buf ) );
                            strncpy( md5Buf, authCheckInp.challenge, CHALLENGE_LEN );
                            parseUserName( _resp->username, username2, userZone );
                            getZoneServerId( userZone, serverId );
                            len = strlen( serverId );
                            if ( len <= 0 ) {
                                rodsLog( LOG_NOTICE, "rsAuthResponse: Warning, cannot authenticate the remote server, no RemoteZoneSID defined in server.config", status );
                                result = ASSERT_ERROR( !requireServerAuth, REMOTE_SERVER_SID_NOT_DEFINED, "Authentication disallowed, no RemoteZoneSID defined." );
                            }
                            else {
                                strncpy( md5Buf + CHALLENGE_LEN, serverId, len );
                                MD5_Init( &context );
                                MD5_Update( &context, ( unsigned char* )md5Buf, CHALLENGE_LEN + MAX_PASSWORD_LEN );
                                MD5_Final( ( unsigned char* )digest, &context );
                                for ( i = 0; i < RESPONSE_LEN; i++ ) {
                                    if ( digest[i] == '\0' ) {
                                        digest[i]++;
                                    }  /* make sure 'string' doesn't
                                          end early*/
                                }
                                cp = authCheckOut->serverResponse;
                                OK = 1;
                                for ( i = 0; i < RESPONSE_LEN; i++ ) {
                                    if ( *cp++ != digest[i] ) {
                                        OK = 0;
                                    }
                                }
                                rodsLog( LOG_DEBUG, "serverResponse is OK/Not: %d", OK );
                                result = ASSERT_ERROR( OK != 0, REMOTE_SERVER_AUTHENTICATION_FAILURE, "Authentication disallowed, server response incorrect." );
                            }
                        }
                    }
                }

                /* Set the clientUser zone if it is null. */
                if ( result.ok() && strlen( _ctx.comm()->clientUser.rodsZone ) == 0 ) {
                    zoneInfo_t *tmpZoneInfo;
                    status = getLocalZoneInfo( &tmpZoneInfo );
                    if ( ( result = ASSERT_ERROR( status >= 0, status, "getLocalZoneInfo failed." ) ).ok() ) {
                        strncpy( _ctx.comm()->clientUser.rodsZone, tmpZoneInfo->zoneName, NAME_LEN );
                    }
                }


                /* have to modify privLevel if the icat is a foreign icat because
                 * a local user in a foreign zone is not a local user in this zone
                 * and vice versa for a remote user
                 */
                if ( result.ok() && rodsServerHost->rcatEnabled == REMOTE_ICAT ) {

                    /* proxy is easy because rodsServerHost is based on proxy user */
                    if ( authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH ) {
                        authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                    }
                    else if ( authCheckOut->privLevel == LOCAL_USER_AUTH ) {
                        authCheckOut->privLevel = REMOTE_USER_AUTH;
                    }

                    /* adjust client user */
                    if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName ) == 0 ) {
                        authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                    }
                    else {
                        zoneInfo_t *tmpZoneInfo;
                        status = getLocalZoneInfo( &tmpZoneInfo );
                        if ( ( result = ASSERT_ERROR( status >= 0, status, "getLocalZoneInfo failed." ) ).ok() ) {
                            if ( strcmp( tmpZoneInfo->zoneName,  _ctx.comm()->clientUser.rodsZone ) == 0 ) {
                                /* client is from local zone */
                                if ( authCheckOut->clientPrivLevel == REMOTE_PRIV_USER_AUTH ) {
                                    authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                                }
                                else if ( authCheckOut->clientPrivLevel == REMOTE_USER_AUTH ) {
                                    authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                                }
                            }
                            else {
                                /* client is from remote zone */
                                if ( authCheckOut->clientPrivLevel == LOCAL_PRIV_USER_AUTH ) {
                                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                                }
                                else if ( authCheckOut->clientPrivLevel == LOCAL_USER_AUTH ) {
                                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                                }
                            }
                        }
                    }
                }
                else if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName ) == 0 ) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }

                if ( result.ok() ) {
                    ret = check_proxy_user_privileges( _ctx.comm(), authCheckOut->privLevel );

                    if ( ( result = ASSERT_PASS( ret, "Check proxy user priviledges failed." ) ).ok() ) {
                        rodsLog( LOG_DEBUG,
                                 "rsAuthResponse set proxy authFlag to %d, client authFlag to %d, user:%s proxy:%s client:%s",
                                 authCheckOut->privLevel,
                                 authCheckOut->clientPrivLevel,
                                 authCheckInp.username,
                                 _ctx.comm()->proxyUser.userName,
                                 _ctx.comm()->clientUser.userName );

                        if ( strcmp( _ctx.comm()->proxyUser.userName,  _ctx.comm()->clientUser.userName ) != 0 ) {
                            _ctx.comm()->proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                            _ctx.comm()->clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
                        }
                        else {          /* proxyUser and clientUser are the same */
                            _ctx.comm()->proxyUser.authInfo.authFlag =
                                _ctx.comm()->clientUser.authInfo.authFlag = authCheckOut->privLevel;
                        }

                    }
                }
            }
        }
        if ( authCheckOut != NULL ) {
            if ( authCheckOut->serverResponse != NULL ) {
                free( authCheckOut->serverResponse );
            }

            free( authCheckOut );
        }
    }
    return result;
}

irods::error krb_auth_agent_verify(
    irods::plugin_context&, const char*, const char*, const char*) {
    return SUCCESS();
}
#endif

/// @brief The krb auth plugin
class krb_auth_plugin : public irods::auth {
public:
    /// @brief Constructor
    krb_auth_plugin(
        const std::string& _name, // instance name
        const std::string& _ctx   // context
        ) : irods::auth( _name, _ctx ) { }

    /// @brief Destructor
    ~krb_auth_plugin() { }

}; // class krb_auth_plugin

/// @brief factory function to provide an instance of the plugin
extern "C"
irods::auth* plugin_factory(
    const std::string& _inst_name, // The name of the plugin
    const std::string& _context ) { // The context
    irods::auth* result = NULL;
    irods::error ret;
    // create a krb auth object
    krb_auth_plugin* krb = new krb_auth_plugin( _inst_name, _context );

    if ( ( ret = ASSERT_ERROR( krb != NULL, SYS_MALLOC_ERR, "Failed to allocate a krb plugin: \"%s\".",
                               _inst_name.c_str() ) ).ok() ) {
        using namespace irods;
        krb->add_operation( irods::AUTH_ESTABLISH_CONTEXT, std::function<error(plugin_context&)>(krb_auth_establish_context) );
        krb->add_operation<rcComm_t*,const char*>( irods::AUTH_CLIENT_START, std::function<error(plugin_context&,rcComm_t*,const char*)>(krb_auth_client_start));
        krb->add_operation<rcComm_t*>( irods::AUTH_CLIENT_AUTH_REQUEST, std::function<error(plugin_context&,rcComm_t*)>(krb_auth_client_request ));
        krb->add_operation<rcComm_t*>( irods::AUTH_CLIENT_AUTH_RESPONSE, std::function<error(plugin_context&,rcComm_t*)>(krb_auth_client_response ));
#ifdef RODS_SERVER
        krb->add_operation<const char*>( irods::AUTH_AGENT_START, std::function<error(plugin_context&,const char*)>(krb_auth_agent_start) );
        krb->add_operation( irods::AUTH_AGENT_AUTH_REQUEST, std::function<error(plugin_context&)>(krb_auth_agent_request ));
        krb->add_operation<authResponseInp_t*>( irods::AUTH_AGENT_AUTH_RESPONSE, std::function<error(plugin_context&,authResponseInp_t*)>(krb_auth_agent_response) );
        krb->add_operation<const char*,const char*,const char*>( irods::AUTH_AGENT_AUTH_VERIFY,  std::function<error(plugin_context&,const char*,const char*,const char*)>(krb_auth_agent_verify) );
#endif
        result = dynamic_cast<irods::auth*>( krb );
        if ( !( ret = ASSERT_ERROR( result != NULL, SYS_INVALID_INPUT_PARAM, "Failed to dynamic cast to irods::auth*" ) ).ok() ) {
            irods::log( ret );
        }
    }
    else {
        irods::log( ret );
    }
    return result;
}
