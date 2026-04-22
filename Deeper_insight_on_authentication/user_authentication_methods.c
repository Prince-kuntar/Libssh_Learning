#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(){
    ssh_session my_ssh_session = NULL;
    int verbosity = SSH_LOG_PROTOCOL;
    int port = 22;
    int rc;
    char *password;

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    //set options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "c2");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

    //connecting to the server
    //if the connection is ok, it returns SSH_OK. Otherwise, it returns SSH_ERROR.
    //if the connection fails, we print the error message using ssh_get_error() for plain english and exit.
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)   {
        fprintf(stderr, "Error connecting to server: %s\n",
                ssh_get_error(my_ssh_session));
        exit(-1);
    }
    //verify the server's identity
    if (verify_knownhost(my_ssh_session) < 0) {
        fprintf(stderr, "Error verifying server identity\n");
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    //getting banner
    rc = display_banner(my_ssh_session);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error getting banner: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    
    //check available authentication methods and authenticate using the first available method.
    rc = check_available_auth_methods(my_ssh_session);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with available methods: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
 
   


    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return 0;
}

//check available authentication methods and authenticate using the first available method.
int check_available_auth_methods(ssh_session session)
{
  int method, rc;
 
  rc = ssh_userauth_none(session, NULL);
  if (rc == SSH_AUTH_SUCCESS || rc == SSH_AUTH_ERROR) {
      return rc;
  }
 
  method = ssh_userauth_list(session, NULL);
 
  if (method & SSH_AUTH_METHOD_NONE)
  {
    rc = authenticate_none(session);
    if (rc == SSH_AUTH_SUCCESS) return rc;
  }
  if (method & SSH_AUTH_METHOD_PUBLICKEY)
  { 
    rc = authenticate_pubkey(session);
    if (rc == SSH_AUTH_SUCCESS) return rc;
  }
  if (method & SSH_AUTH_METHOD_INTERACTIVE)
  {
    rc = authenticate_kbdint(session);
    if (rc == SSH_AUTH_SUCCESS) return rc;
  }
  if (method & SSH_AUTH_METHOD_PASSWORD)
  {
    rc = authenticate_password(session);
    if (rc == SSH_AUTH_SUCCESS) return rc;
  }
  return SSH_AUTH_ERROR;
}

//password authentication
int authenticate_password(ssh_session session)
{
    char *password;
    int rc;

    password = getpass("Enter your password: ");
    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(session));
        return rc;
    }
    return SSH_AUTH_SUCCESS;
}

//no password authentication
int authenticate_none(ssh_session session)
{
    int rc;

    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_AUTH_SUCCESS) {
        return SSH_AUTH_SUCCESS;
    }
    else if (rc == SSH_AUTH_ERROR) {
        fprintf(stderr, "Error authenticating with none: %s\n",
                ssh_get_error(session));
        return SSH_AUTH_ERROR;
    }
    return rc;
}

//public key authentication
int authenticate_pubkey(ssh_session session)
{
    int rc;

    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with public key: %s\n",
                ssh_get_error(session));
        return rc;
    }
    return SSH_AUTH_SUCCESS;
}

//keyboard-interactive authentication
int authenticate_kbdint(ssh_session session)
{
    int rc;

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with keyboard-interactive: %s\n",
                ssh_get_error(session));
        return rc;
    }
    return SSH_AUTH_SUCCESS;
}

//func to display banner
int display_banner(ssh_session session)
{
  int rc;
  char *banner = NULL;
 
//older versions needed this
//not ready needed in new versions, here just fir certainity and reference
  rc = ssh_userauth_none(session, NULL);
  if (rc == SSH_AUTH_ERROR)
    return rc;
 
  banner = ssh_get_issue_banner(session);
  if (banner)
  {
    printf("%s\n", banner);
    free(banner);
  }
 
  return rc;
}