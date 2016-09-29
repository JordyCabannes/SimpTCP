# SimpTCP  

##Introduction
During my third year at INSA Toulouse, we had to design a network protocol which mixed TC and UDP features. This network protocol works with SYN, SYN-ACK, ACK when establishing the connexion between a custom and a server. The custom can send PDU package and the server received this package and send an ACK.  
We implemented the following functions in the file src/simptcp_lib.c :  
- closed_simptcp_socket_state_active_open,   
- closed_simptcp_socket_state_passive_open,   
- listen_simptcp_socket_state_accept,   
- listen_simptcp_socket_state_close,   
- listen_simptcp_socket_state_process_simptcp_pdu,   
- synsent_simptcp_socket_state_process_simptcp_pdu,   
- synsent_simptcp_socket_state_handle_timeout,   
- synrcvd_simptcp_socket_state_process_simptcp_pdu,   
- synrcvd_simptcp_socket_state_handle_timeout,   
- established_simptcp_socket_state_send,   
- established_simptcp_socket_state_recv,   
- established_simptcp_socket_state_shutdown,   
- established_simptcp_socket_state_process_simptcp_pdu,   
- established_simptcp_socket_state_handle_timeout,   
- finwait1_simptcp_socket_state_process_simptcp_pdu,   
- timewait_simptcp_socket_state_process_simptcp_pdu,   
- timewait_simptcp_socket_state_handle_timeout.  
  
##Installation
- Download the folder.
- Check that there is not .o files in src folder. If there is .o files delete them.
- With the terminal, go to the folder of the project and tip the command "make"

##Test
- Open two terminal windows, in each window, go to the folder of the project.
- In one of the window tip the command :  ./build/server 8000  
- Then in the second window tip the command :  ./build/client localhost 8000  
- Then in the second terminal window you can enter a message. When you have finished to write your message press "enter" button.
- You will see your message on the first one terminal window and the connection will be closed.
- If you want to test again you will have to delete all the .o files in the src folder.
