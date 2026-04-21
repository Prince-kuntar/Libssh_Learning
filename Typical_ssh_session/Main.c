#include <libssh/libssh.h>
#include <stdlib.h>

int main(){
    ssh_session my_ssh_session = NULL;
    int verbosity = SSH_LOG_PROTOCOL;
    int port = 22;

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    //set options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "c2");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

    //more goes here, such as ssh_connect(), ssh_userauth_password(), etc.
    ssh_free(my_ssh_session);
    return 0;
}