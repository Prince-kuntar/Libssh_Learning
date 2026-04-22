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

    //user authentication
    password = getpass("Enter your password: ");
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    //execute a command on the remote server and print the output.
    if (show_remote_processes(my_ssh_session) != SSH_OK) {
        fprintf(stderr, "Error executing remote command: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }


    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return 0;
}

//verify the server's identity by checking its public key against the known hosts file. 
//This is a crucial step

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *p = NULL;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    //the recommended way to check the validity of the server by checking its hostname pattern and compare with known hosts file. 
    //The function ssh_session_is_known_server() returns an enum ssh_known_hosts_e that can be used to determine the state of the server.   
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
            //action will happen here if the server is known and matches the known hosts file. In this case, we can proceed with the connection without any warnings.
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: ");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

//execeute a command on the remote server and print the output.
//Doing something example
int show_remote_processes(ssh_session session)
{
  ssh_channel channel = NULL;
  int rc;
  char buffer[256];
  int nbytes;
 
  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
 
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
 
  rc = ssh_channel_request_exec(channel, "ps aux");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
 
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != (unsigned int) nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
 
  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
 
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
 
  return SSH_OK;
}