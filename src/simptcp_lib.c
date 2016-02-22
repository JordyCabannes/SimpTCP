/*! \file simptcp_lib.c
*  \brief{Defines the functions that gather the actions performed by a simptcp protocol entity in reaction to events (system calls, simptcp packet arrivals, timeouts) given its state at a point in time  (closed, ..established,..).} 
*  \author{DGEI-INSAT 2010-2011}
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>              /* for errno macros */
#include <sys/socket.h>
#include <netinet/in.h>         /* for htons,.. */
#include <arpa/inet.h>
#include <unistd.h>             /* for usleep() */
#include <sys/time.h>           /* for gettimeofday,..*/

#include <libc_socket.h>
#include <simptcp_packet.h>
#include <simptcp_entity.h>
#include "simptcp_func_var.c"    /* for socket related functions' prototypes */
#include <term_colors.h>        /* for color macros */
#define __PREFIX__              "[" COLOR("SIMPTCP_LIB", BRIGHT_YELLOW) " ] "
#include <term_io.h>

#ifndef __DEBUG__
#define __DEBUG__               1
#endif


int indice_fils;
int nb_transmission;
int not_extract_data = 0 ;

//fonction pour forger un pdu 
void forger_pdu(struct  simptcp_socket * sock ,u_char type_flag)
{
	simptcp_set_sport(sock->out_buffer, htons(sock->local_simptcp.sin_port));	
	simptcp_set_dport(sock->out_buffer, htons(sock->remote_simptcp.sin_port));
	simptcp_set_flags(sock->out_buffer, type_flag);
	simptcp_set_seq_num(sock->out_buffer, sock->next_seq_num);
	simptcp_set_ack_num(sock->out_buffer, sock->next_ack_num);

	simptcp_set_head_len(sock->out_buffer, SIMPTCP_GHEADER_SIZE);
	simptcp_set_total_len(sock->out_buffer, SIMPTCP_GHEADER_SIZE);
	simptcp_set_win_size(sock->out_buffer, SIMPTCP_SOCKET_MAX_BUFFER_SIZE - sock->in_len  ); //taille du buffer à l'envoi
	simptcp_add_checksum (sock->out_buffer, SIMPTCP_GHEADER_SIZE);
	sock->next_seq_num++;
	//printf("taille check sum dans close ; %d\n",simptcp_get_checksum(sock->out_buffer));*/	
}

void forger_pdu_message(struct  simptcp_socket * sock,char * charge_utile,u_char type_flag)//flag 0 pour les données 
{
	simptcp_set_sport(sock->out_buffer, htons(sock->local_simptcp.sin_port));	
	simptcp_set_dport(sock->out_buffer, htons(sock->remote_simptcp.sin_port));
	simptcp_set_seq_num(sock->out_buffer, sock->next_seq_num);
	simptcp_set_ack_num(sock->out_buffer, sock->next_ack_num);
	simptcp_set_flags(sock->out_buffer, type_flag);

	memcpy(sock->out_buffer+SIMPTCP_GHEADER_SIZE,charge_utile,sizeof(charge_utile));
	//simptcp_set_head_len(sock->out_buffer, SIMPTCP_GHEADER_SIZE);
	simptcp_set_total_len(sock->out_buffer, SIMPTCP_GHEADER_SIZE+sizeof(charge_utile));
	simptcp_add_checksum (sock->out_buffer, SIMPTCP_GHEADER_SIZE+sizeof(charge_utile));
	printf("..............................................................taille message dans  forger_pdu_message : %d  \n " ,SIMPTCP_GHEADER_SIZE+sizeof(charge_utile) );
	sock->next_seq_num++;

	
}

/*! \fn char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state)
* \brief renvoie une chaine correspondant a l'etat dans lequel se trouve un socket simpTCP. Utilisee a des fins d'affichage
* \param state correspond typiquement au champ socket_state de la structure #simptcp_socket qui indirectement identifie l'etat dans lequel le socket se trouve et les fonctions qu'il peut appeler depuis cet etat
* \return chaine de carateres correspondant a l'etat dans lequel se trouve le socket simpTCP
*/
char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state) {
    if (state == &  simptcp_socket_states.closed)
	return "CLOSED";
    else if (state == & simptcp_socket_states.listen)
	return "LISTEN";
    else if (state == & simptcp_socket_states.synsent)
	return "SYNSENT";
    else if (state == & simptcp_socket_states.synrcvd)
	return "SYNRCVD";
    else if (state == & simptcp_socket_states.established)
	return "ESTABLISHED";
    else if (state == & simptcp_socket_states.closewait)
	return "CLOSEWAIT";
    else if (state == & simptcp_socket_states.finwait1)
	return "FINWAIT1";
    else if (state == & simptcp_socket_states.finwait2)
	return "FINWAIT2";
    else if (state == & simptcp_socket_states.closing)
	return "CLOSING";
    else if (state == & simptcp_socket_states.lastack)
	return "LASTACK";
    else if (state == & simptcp_socket_states.timewait)
	return "TIMEWAIT";
    else
	assert(0);
}

/**
 * \brief called at socket creation 
 * \return the first sequence number to be used by the socket
 * \TODO: randomize the choice of the sequence number to fit TCP behaviour..
 */
unsigned int get_initial_seq_num()
{
  unsigned int init_seq_num=15; 
#if __DEBUG__
	printf("function %s called\n", __func__);
#endif

    return init_seq_num;
}


/*!
* \brief Initialise les champs de la structure #simptcp_socket
* \param sock pointeur sur la structure simptcp_socket associee a un socket simpTCP 
* \param lport numero de port associe au socket simptcp local 
*/
void init_simptcp_socket(struct simptcp_socket *sock, unsigned int lport)
{
    
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    
    assert(sock != NULL);
    pthread_mutex_init(&(sock->mutex_socket), NULL);
    
    lock_simptcp_socket(sock);
    
    /* Initialization code */
    
    sock->socket_type = unknown;
    sock->new_conn_req=NULL;
    sock->pending_conn_req=0;
    
    /* set simpctp local sockr :12et address */
    memset(&(sock->local_simptcp), 0, sizeof (struct sockaddr));
    sock->local_simptcp.sin_family = AF_INET;
    sock->local_simptcp.sin_addr.s_addr = htonl(INADDR_ANY);
    sock->local_simptcp.sin_port = htons(lport);
    
    memset(&(sock->remote_simptcp), 0, sizeof (struct sockaddr));
    
    
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
    
    /* protocol entity sending side */
    sock->socket_state_sender=-1;
    sock->next_seq_num=get_initial_seq_num();
    memset(sock->out_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);
    sock->out_len=0;
    sock->nbr_retransmit=0;
    sock->timer_duration=1500;
    /* protocol entity receiving side */
    sock->socket_state_receiver=-1;
    sock->next_ack_num=0;
    memset(sock->in_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);
    sock->in_len=0;
    
    /* timeut initialization */
    sock->timeout.tv_sec=0;
    sock->timeout.tv_usec=0;
    /* MIB statistics initialisation  */
    sock->simptcp_send_count=0;
    sock->simptcp_receive_count=0;
    sock->simptcp_in_errors_count=0;
    sock->simptcp_retransmit_count=0;
    
    
    /* Add Optional field initialisations */
    unlock_simptcp_socket(sock);
    
}


/*! \fn int create_simptcp_socket()
* \brief cree un nouveau socket SimpTCP et l'initialise. 
* parcourt la table de  descripteur a la recheche d'une entree libre. S'il en trouve, cree
* une nouvelle instance de la structure simpTCP, la rattache a la table de descrpteurs et l'initialise. 
* \return descripteur du socket simpTCP cree ou une erreur en cas d'echec
*/
int create_simptcp_socket()
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	
	int fd;
    struct simptcp_socket*  new_sock;
    
    
    /* get a free simptcp socket descriptor */
    for (fd=0;fd< MAX_OPEN_SOCK;fd++) {
        if ((simptcp_entity.simptcp_socket_descriptors[fd]) == NULL){
            /* this is a free descriptor */
            /* Allocating memory for the new simptcp_socket */
            new_sock =
            (struct simptcp_socket *) malloc(sizeof(struct simptcp_socket));
            if (!new_sock) {
                return -ENOMEM;
            }
            /* initialize the simptcp socket control block with
             local port number set to 15000+fd */
            init_simptcp_socket(new_sock,15000+fd);
            simptcp_entity.open_simptcp_sockets++;
            
            simptcp_entity.simptcp_socket_descriptors[fd]=new_sock;
            /* return the socket descriptor */
            return fd;
        }
    } /* for */
    /* The maximum number of open simptcp
     socket reached  */
    return -ENFILE; 
}

/*! \fn void print_simptcp_socket(struct simptcp_socket *sock)
* \brief affiche sur la sortie standard les variables d'etat associees a un socket simpTCP 
* Les valeurs des principaux champs de la structure simptcp_socket d'un socket est affichee a l'ecran
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
void print_simptcp_socket(struct simptcp_socket *sock)
{
    printf("----------------------------------------\n");
    printf("local simptcp address: %s:%hu \n",inet_ntoa(sock->local_simptcp.sin_addr),ntohs(sock->local_simptcp.sin_port));
    printf("remote simptcp address: %s:%hu \n",inet_ntoa(sock->remote_simptcp.sin_addr),ntohs(sock->remote_simptcp.sin_port));   
    printf("socket type      : %d\n", sock->socket_type);
    printf("socket state: %s\n",simptcp_socket_state_get_str(sock->socket_state) );
    if (sock->socket_type == listening_server)
      printf("pending connections : %d\n", sock->pending_conn_req);
    printf("sending side \n");
    printf("sender state       : %d\n", sock->socket_state_sender);
    printf("transmit  buffer occupation : %d\n", sock->out_len);
    printf("next sequence number : %u\n", sock->next_seq_num);
    printf("retransmit number : %u\n", sock->nbr_retransmit);

    printf("Receiving side \n");
    printf("receiver state       : %d\n", sock->socket_state_receiver);
    printf("Receive  buffer occupation : %d\n", sock->in_len);
    printf("next ack number : %u\n", sock->next_ack_num);

    printf("send count       : %lu\n", sock->simptcp_send_count);
    printf("receive count       : %lu\n", sock->simptcp_receive_count);
    printf("receive error count       : %lu\n", sock->simptcp_in_errors_count);
    printf("retransmit count       : %lu\n", sock->simptcp_retransmit_count);
    printf("----------------------------------------\n");
}


/*! \fn inline int lock_simptcp_socket(struct simptcp_socket *sock)
* \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
* Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
* l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
* Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
* Avant tout  acces en ecriture a ces variables, l'appel a cette fonction permet 
* 1- si le semaphore est disponible (unlocked) de placer le semaphore dans une etat indisponible 
* 2- si le semaphore est indisponible, d'attendre jusqu'a ce qu'il devienne disponible avant de le "locker"
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
int lock_simptcp_socket(struct simptcp_socket *sock)
{
#if __DEBUG__
	printf("function %s called\n", __func__);
#endif   

    if (!sock)
        return -1;

    return pthread_mutex_lock(&(sock->mutex_socket));
}

/*! \fn inline int unlock_simptcp_socket(struct simptcp_socket *sock)
* \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
* Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
* l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
* Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
* Après un acces "protege" en ecriture a ces variables, l'appel a cette fonction permet de liberer le semaphore 
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
int unlock_simptcp_socket(struct simptcp_socket *sock)
{
#if __DEBUG__
	printf("function %s called\n", __func__);
#endif   

    if (!sock)
        return -1;

    return pthread_mutex_unlock(&(sock->mutex_socket));
}

/*! \fn void start_timer(struct simptcp_socket * sock, int duration)
 * \brief lance le timer associe au socket en fixant l'instant ou la duree a mesurer "duration" sera ecoulee (champ "timeout" de #simptcp_socket)
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \param duration duree a mesurer en ms
*/
void start_timer(struct simptcp_socket * sock, int duration)
{
  struct timeval t0;
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
  assert(sock!=NULL);
  
  gettimeofday(&t0,NULL);
  
  sock->timeout.tv_sec=t0.tv_sec + (duration/1000);
  sock->timeout.tv_usec=t0.tv_usec + (duration %1000)*1000;  
}

/*! \fn void stop_timer(struct simptcp_socket * sock)
 * \brief stoppe le timer en reinitialisant le champ "timeout" de #simptcp_socket
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
void stop_timer(struct simptcp_socket * sock)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif  
  assert(sock!=NULL); //sock->socket_state_sender = wait_message;
  sock->timeout.tv_sec=0;
  sock->timeout.tv_usec=0; 
}

/*! \fn int has_active_timer(struct simptcp_socket * sock)
 * \brief Indique si le timer associe a un socket simpTCP est actif ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si timer actif, 0 sinon
 */
int has_active_timer(struct simptcp_socket * sock)
{
  return (sock->timeout.tv_sec!=0) || (sock->timeout.tv_usec!=0);
}

/*! \fn int is_timeout(struct simptcp_socket * sock)
 * \brief Indique si la duree mesuree par le timer associe a un socket simpTCP est actifs'est ecoulee ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si duree ecoulee, 0 sinon
 */
int is_timeout(struct simptcp_socket * sock)
{
  struct timeval t0;

  assert(sock!=NULL);
  /* make sure that the timer is launched */
  assert(has_active_timer(sock));
  
  gettimeofday(&t0,NULL);
  return ((sock->timeout.tv_sec < t0.tv_sec) || 
	  ( (sock->timeout.tv_sec == t0.tv_sec) && (sock->timeout.tv_usec < t0.tv_usec)));
}


/*** socket state dependent functions ***/


/*********************************************************
 * closed_state functions *
 *********************************************************/

/*! \fn int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
	

	int sortie_du_sendto; //retour de la fonction sendto
	sock->socket_type=client; //c'est un client 
	
	//initilisation de la socket simptcp avec l'@ distante                                             
	memcpy(&(sock->remote_simptcp), addr, len);                  

	memcpy(&(sock->remote_udp), addr, len);
	
	forger_pdu(sock,SYN);//on forge le pdu SYN

	if (simptcp_entity.udp_fd==-1)
	{
		printf("erreur création socket  \n");
		exit(1);
	}
	simptcp_lprint_packet(sock->out_buffer);//on affiche le pdu SYN 
	
	//envoie du pdu syn 	
	sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,sock->out_buffer,SIMPTCP_GHEADER_SIZE ,0,(struct sockaddr * )(&(sock->remote_udp)),len) ;  
	start_timer(sock, sock->timer_duration);	
	if(sortie_du_sendto==-1)
	{
		printf("erreur : echec envoi \n"); 
		//exit(1);
	} 
	//printf("sortie du sendto : %d\n",sortie_du_sendto);
	
	//Changement d'état du socket émetteur, on passe en synsent
	sock->socket_state = &(simptcp_entity.simptcp_socket_states->synsent);
	

	//debug
	printf("\n état actuel client  : %s , num_seq : %d \n",simptcp_socket_state_get_str(sock->socket_state) ,sock->next_seq_num);

	//permet d'attendre d'avoir établie la connexion pour demander l'écriture du message à envoyer
	 while (sock->socket_state != &(simptcp_entity.simptcp_socket_states->established) && sock->socket_state != &(simptcp_entity.simptcp_socket_states->closed)) {} 
	
	
	
	//dés que l'on est en established , on affiche  ce message 
	printf(" established coté client  \n ") ;
		

    return 0;
}


/*! \fn int closed_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{ 
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	lock_simptcp_socket(sock);	
	sock-> socket_type=listening_server; //c'est un server 
	sock->max_conn_req_backlog=n;	
	sock->new_conn_req = malloc (n*sizeof(struct simptcp_socket **)); //on alloue le tableau contenant les connexions entrantes 
	unlock_simptcp_socket(sock);
	//on passe dans l'état listen 
	sock->socket_state = &(simptcp_entity.simptcp_socket_states->listen);

	//debug 
	printf("\n état actuel du serveur  : %s \n" ,simptcp_socket_state_get_str(sock->socket_state));

  return 0;
}


/*! \fn int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
  return 0;//à  mettre à -1
}


/*! \fn ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
  return -1;//0
}


/*! \fn ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
  return -1;//0
}

/**
 * called when application calls close
 */

/*! \fn  int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
 
  return -1;//0
}

/*! \fn  int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur while (sock->socket_state != &(simptcp_entity.simptcp_socket_states->established) && sock->socket_state != &(simptcp_entity.simptcp_socket_states->closed)) {
 */
int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
  return -1;//0

}

/*! 
 * \fn void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}






/*********************************************************
 * listen_state functions *
 *********************************************************/

/*! \fn int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
#if __DEBUG__ 
    printf("function %s called\n", __func__);
#endif

	printf("\n fonction : 1 \n");
    return -1;//0   
}


	
 /* called when application calls listen
 */
/*! \fn int listen_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les varsock->socket_state_sender = wait_message;iables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{sock->socket_state_sender = wait_message;
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	printf("\n fonction : 2 \n");
    return -1;//à verifier 
}

/**
 * called when application calls accept
 */
/*! \fn int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	printf("\n fonction : 3  \n");
	int sortie_du_sendto ;
	
	//simptcp_lprint_packet(sock->out_buffer);//on affiche le contenu du buffer 
	printf("en attente du pdu de connexion entrante ...\n ") ;
	while (sock->pending_conn_req<1) 
	{
		usleep(10); 
		//printf("bisounours :) \n");
	}
	
	// On récupère dans le tableau des nouvelles connections ,la socket contenant les informations sur la socket emettrice du SYN
	//il s'agit de la socket que l'on a stockée lors de l'appel de la fonction  listen_simptcp_socket_state_process_simptcp_pdu() 
	sock->pending_conn_req--; 
	struct simptcp_socket *socket_envoie_syn_ack = sock->new_conn_req[sock->pending_conn_req ];
	printf(" Etat du fils : %s \n :" , simptcp_socket_state_get_str(socket_envoie_syn_ack->socket_state));
	 

	//permet d'initialiser coté serveur le numéro de séquence pour ne pas avoir d'erreurs lors de 
	//la récéption de l'ack	
	socket_envoie_syn_ack->next_seq_num=sock->next_ack_num;
	sock->next_seq_num=socket_envoie_syn_ack->next_seq_num;

	// .. on rajoute la socket créée au tableau des descripteurs 
	if (simptcp_entity.open_simptcp_sockets < MAX_OPEN_SOCK) 
	{
		simptcp_entity.simptcp_socket_descriptors[simptcp_entity.open_simptcp_sockets] = socket_envoie_syn_ack;
		
		
	}

	
	printf("On renvoie un PDU SYN-ACK\n");
	//on a recu le syn , on envoie le synack puis on passe à l'etat synrcvd 
	forger_pdu(socket_envoie_syn_ack,SYN+ACK);
	//on affiche le pdu forger pour vérification 
	simptcp_lprint_packet(socket_envoie_syn_ack->out_buffer) ;
	sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,socket_envoie_syn_ack->out_buffer,MAX_SIMPTCP_BUFFER_SIZE ,0,(struct sockaddr * )(&(socket_envoie_syn_ack->remote_udp)),*len) ;
	//On lance un timer
	start_timer(sock, sock->timer_duration);

	if(sortie_du_sendto==-1)
	{
		printf("*****************************erreur : echec envoi du syn-ack \n"); 
		//exit(1);
	} 

	socket_envoie_syn_ack->socket_state = &(simptcp_entity.simptcp_socket_states->synrcvd); //on est dans l'etat Synrcvd
	printf(" Etat du fils : %s \n :" , simptcp_socket_state_get_str(socket_envoie_syn_ack->socket_state));	

	sock->socket_state = &(simptcp_entity.simptcp_socket_states->synrcvd); //le serveur principal passe en synrcvd puisqu'il a géré toutes les connexions entrantes 
	
	while (sock->socket_state != &simptcp_socket_states.established){} // tant qu'on est pas en established , le serveur continue de tourner
	
	sock->socket_state=&(simptcp_entity.simptcp_socket_states->listen);
	socket_envoie_syn_ack->socket_state = &(simptcp_entity.simptcp_socket_states->established); //on est dans l'etat Synrcvd
	printf(" Etat du fils : %s \n :" , simptcp_socket_state_get_str(socket_envoie_syn_ack->socket_state));	
	
	printf(" Etat du père : %s \n :" , simptcp_socket_state_get_str(sock->socket_state));

	 
	
	simptcp_entity.open_simptcp_sockets++;

	sock-> socket_type=listening_server; //c'est un server 
	sock->local_simptcp.sin_port=0; //on réinitialise les informations du pere pour pouvoir travailler sur la socket fils

	indice_fils=simptcp_entity.open_simptcp_sockets-1;
  return (simptcp_entity.open_simptcp_sockets-1); //renvoie le numéro de descripteur de la socket fils
}

/**
 * called when application calls send
 */
/*! \fn ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	printf("\n fonction : 4 \n"); 
    return -1;//0
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	printf("\n fonction : 5 \n");

    return -1;//0

}

/**
 * called when application calls close
 */
/*! \fn  int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	printf("\n fonction : 6 \n");

	// Passage à l'état closed, delete TCB
    stop_timer(sock);
    sock->nbr_retransmit = 0;
    free(sock->new_conn_req);       //On libère la pile utilisé.
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
    return 0;//à vérifier 

}
/**
 * called when application calls shutdown
 */
/*! \fn  int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
	printf("\n fonction : 7 \n");
  return -1;//à vérifier

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe u_sockn PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	//démultiplexage du syn 
	//printf("\n fonction : 8 \n");
	//simptcp_lprint_packet(buf); 
	
	//printf("--------------------------------------------\n") ;
	//var = 1 ;
	//if (sock->pending_conn_req==0){
	if (simptcp_get_flags(buf) == SYN) 
	{
		printf("***************************** pdu syn recu ********************************\n");
		simptcp_lprint_packet(buf); //On affiche le PDU reçu
		printf("***************************************************************************\n");
		//sock->socket_state = &(simptcp_entity.simptcp_socket_states->synrcvd); // on passe à l'etat synreceiv 
		
		// Creation d'une socket SymTcp qui va contenir toutes les informations sur la socket qui nous a envoyé 
		//le syn , et qui va nous permettre de lui envoyer le SYN-ACK,
		
		struct simptcp_socket * socket_syn_ack = malloc(sizeof(struct simptcp_socket));
		if (socket_syn_ack!=NULL) 
		{
			socket_syn_ack->socket_state = &(simptcp_entity.simptcp_socket_states->synrcvd); // le nouveau serveur passe en synreceivd
			socket_syn_ack->socket_type = nonlistening_server;
			socket_syn_ack->remote_simptcp = sock->remote_simptcp;
			socket_syn_ack->remote_udp = sock->remote_udp;
			socket_syn_ack->local_simptcp=sock->local_simptcp;
			socket_syn_ack->next_ack_num = simptcp_get_seq_num(buf) + 1; 
		
			sock->pending_conn_req++; 

			// on rajoute la socket new_sock dans le tableau des new_conn_req , pour pouvoir la recuperer et renvoyer 
			//le Syn-ack à la bonne socket simtcp qui nous a envoyé le syn via la fonction listen_simptcp_socket_state_accept()
			sock->new_conn_req[sock->pending_conn_req - 1] = socket_syn_ack;
			//printf("*********************** num : %d\n", simptcp_entity.open_simptcp_sockets);
			/*if (simptcp_entity.open_simptcp_sockets < MAX_OPEN_SOCK) 
			{
				//on répertorie toutes les sockets dans le tableau des descripteurs 
				printf("______________________________  NUM dans tableau :   %d\n", simptcp_entity.open_simptcp_sockets);
				simptcp_entity.simptcp_socket_descriptors[simptcp_entity.open_simptcp_sockets] = socket_syn_ack;
				//simptcp_entity.open_simptcp_sockets++;
			}
		}else
		{
			printf(" nombre de connexion maximum atteinte  \n");
			exit(1);
		}*/
	}//}

}
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	printf("\n fonction : 9 \n");
}


/*********************************************************
 * synsent_state functions *_sock
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variablif (simptcp_get_flags(buf) == ACK) {
    printf("ACK reçu\n");
    // changement d'état
    sock->socket_state = &simptcp_socket_states.established;es d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock,struct sockaddr* addr, socklen_t len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	printf("synsent 1 \n") ;
    return -1;//à vérifier
   
}

/**
 * called when application calls listen
 */
/*! \fn int synsent_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 2\n") ;
    return -1;//0

}

/**&simptcp_socket_states.
 * called when applicasend_to_sockettion calls accept
 */
/*! \fn int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables &simptcp_socket_states.d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 3 \n") ;
    return -1;//0

}

/**send_to_socket
 * called when application calls send
 */
/*! \fn ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsqu&simptcp_socket_states.e l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en oc&simptcp_socket_states.tet du message envoye ; -1 sinon
 */
ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 4 \n") ;
    return -1;//0

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 5 \n") ;
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 6 \n") ;
    return 0;

}

/**&simptcp_socket_states.
 * called when application calls shutdown
 */
/*! \fn  int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		printf("synsent 7 \n") ;
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	printf("synsent  8 : reception du syn+ack \n") ;

	int sortie_du_sendto=-1 ;



	lock_simptcp_socket(sock);
	//si on reçoit un syn-ack et que le numéro d'acquittement est correct 
	if ((simptcp_get_flags(buf) == (SYN+ACK)) && (simptcp_get_ack_num(buf) == sock->next_seq_num) ) 
	{
		 printf("SYNACK reçu\n");
		stop_timer(sock);		
		simptcp_lprint_packet(buf) ;//on affiche le pdu recu 
		
		//printf("SISI LA FAMILLE RPZ #SYNACK DANS LA PLACE \n") ;
		
		sock->next_ack_num=simptcp_get_seq_num(buf);
		forger_pdu(sock,ACK); //on forge le pdu ack pour le renvoyer
		
		printf("********************************************envoie du ack ************************************************\n");
		simptcp_lprint_packet(sock->out_buffer) ;

		
		
		sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, SIMPTCP_GHEADER_SIZE, 0, (struct sockaddr*) (&sock->remote_udp), sizeof(struct sockaddr_in)) ;

		if (sortie_du_sendto==-1)
		{	
			printf("+++++++++++++++++++++++++++erreur envoie ACK\n");
			//exit(1);
		}
		
		sock->socket_state = &(simptcp_entity.simptcp_socket_states->established); //on est dans l'etat established coté client 
		//printf(" established coté client  \n ") ;	
		sock->socket_state_sender = wait_message; 
		unlock_simptcp_socket(sock);

	}
	


}

/**
 * called after a timeout has detsock->socket_state_sender = wait_message;ected
 */
/*! 
 * \fn void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	//on renvoie le syn car time_out
	int sortie_du_sendto;
	
	simptcp_lprint_packet(sock->out_buffer);//on affiche le pdu SYN 
	sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,sock->out_buffer,SIMPTCP_GHEADER_SIZE ,0,(struct sockaddr * )(&(sock->remote_udp)),sizeof(struct sockaddr_in)) ;  
	start_timer(sock, sock->timer_duration);	
	//simptcp_lprint_packet(sock->out_buffer);//on affiche le pdu SYN 
	return 0;
}


/*********************************************************
 * synrcvd_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
	
    printf("function %s called\n", __func__);
#endif
    return -1;//0
   
}

/**
 * called when application calls listen
 */
/*! \fn int synrcvd_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;//0

}

/**
 * called when application calls send
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'applicif (simptcp_get_flags(buf) == ACK) {
    printf("ACK reçu\n");
    // changement d'état
    sock->socket_state = &simptcp_socket_states.established;ation lance l'appel "send" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;//0

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] lesimptcp_lprint_packet(buf) ;n taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;//0

}

/**
 * called when application calls close
 */
/*! \fn  int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etaprintf(" Etat du père : %s \n :" , simptcp_socket_state_get_str(sock->socket_state));t "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /*forger_pdu(sock,FIN);
    simptcp_send(sock, (struct sockaddr*)&sock->remote_udp,sizeof(sock->remote_udp));

    //On démarre le Timer
    start_timer(sock, sock->timer_duration);

    // Passage à l'etat FINWAIT1
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->finwait1);*/
	return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1 ;//0

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	printf("***************************\n");
	printf("***************************\n");
//	printf("%d\n", sock->next_seq_num);
	//si on reçoit un ack et que le num d'acquittement est bon 
	if ((simptcp_get_flags(buf) == ACK) && (simptcp_get_ack_num(buf) == sock->next_seq_num)){
    printf("ACK reçu\n");
		stop_timer(simptcp_entity.simptcp_socket_descriptors[0]);
		sock->nbr_retransmit = 0;
    // changement d'état
	sock->socket_state = &(simptcp_entity.simptcp_socket_states->established);//established coté serveur
	//sock->socket_state_receiver=wait_packet; 
    /*free(sock->in_buffer) ;
	free(simptcp_entity.simptcp_socket_descriptors[1]->in_buffer);
	sock->in_len=0;
	simptcp_entity.simptcp_socket_descriptors[1]->in_len=0;*/
	printf("established côté serveur \n ") ;
	simptcp_lprint_packet(buf);
	}
	// S'il y a un timeout lors de l'envoi du SYN le seveur va recevoir un nouveau SYN et donc on va renvoyer le SYN+ACK
	else if((simptcp_get_flags(buf) == SYN) && simptcp_get_ack_num(buf) < sock->next_seq_num)
	{
		stop_timer(simptcp_entity.simptcp_socket_descriptors[0]);
		printf("Nouveau SYN reçu\n");
		simptcp_lprint_packet(simptcp_entity.simptcp_socket_descriptors[1]->out_buffer) ;
		int sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,simptcp_entity.simptcp_socket_descriptors[1]->out_buffer,MAX_SIMPTCP_BUFFER_SIZE ,0,(struct sockaddr * )(&(simptcp_entity.simptcp_socket_descriptors[1]->remote_udp)),sizeof(struct sockaddr_in)) ;
		//On lance un timer
		start_timer(simptcp_entity.simptcp_socket_descriptors[0], simptcp_entity.simptcp_socket_descriptors[0]->timer_duration);
		if(sortie_du_sendto==-1)
		{
			printf("*****************************erreur : echec envoi du syn-ack \n"); 
			//exit(1);
		}	
	}
	
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	
	

	//time out , on renvoie le syn-ack
	simptcp_lprint_packet(simptcp_entity.simptcp_socket_descriptors[1]->out_buffer) ;
	int sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,simptcp_entity.simptcp_socket_descriptors[1]->out_buffer,MAX_SIMPTCP_BUFFER_SIZE ,0,(struct sockaddr * )(&(simptcp_entity.simptcp_socket_descriptors[1]->remote_udp)),sizeof(struct sockaddr_in)) ;
	//On lance un timer
	start_timer(simptcp_entity.simptcp_socket_descriptors[0], simptcp_entity.simptcp_socket_descriptors[0]->timer_duration);

	if(sortie_du_sendto==-1)
	{
		printf("*****************************erreur : echec envoi du syn-ack \n"); 
		//exit(1);
	} 

}


/*********************************************************
 * established_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int established_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

	 

#if __DEBUG__
  printf("function %s called\n", __func__);
#endif

	int sortie_du_sendto;
	
	if(sock->socket_type == client && (sock->socket_state_sender == wait_message) )
	{

		//reception d'un syn-ack apres un renvoi suite à un time out, on revoie le ack du syn-ack
		if((simptcp_get_flags(buf) == SYN+ACK) && simptcp_get_ack_num(buf) < sock->next_seq_num)
		{
			stop_timer(sock);
			printf("Nouveau SYN+ACK reçu\n");
			simptcp_lprint_packet(sock->out_buffer) ;
			int sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd,sock->out_buffer,MAX_SIMPTCP_BUFFER_SIZE ,0,(struct sockaddr * )(&(sock->remote_udp)),sizeof(struct sockaddr_in)) ;
			//On lance un timer
			start_timer(sock, sock->timer_duration);
			if(sortie_du_sendto==-1)
			{
				printf("*****************************erreur : echec envoi du syn-ack \n"); 
				//exit(1);
			}	
		}
		else
		{
			//reception d'un message en provenance de l'application et envoi du message au serveur 
			sock->next_ack_num=simptcp_get_seq_num(buf);				
			forger_pdu_message(sock, buf,flags);
			//sock->out_buffer=buf;
			sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, SIMPTCP_GHEADER_SIZE+n, 0, (struct sockaddr*) (&sock->remote_udp), sizeof(struct sockaddr_in));
			simptcp_lprint_packet(sock->out_buffer);
			start_timer(sock, sock->timer_duration);
			sock->socket_state_sender = wait_ack;
			while(sock->socket_state_sender == wait_ack) 
			{

				usleep(100);
 			}
	
		}

	}
	return sortie_du_sendto;
		
}
	
  
   
/**
 * called when application calls recv
 */
/*! \fn ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
  printf("function %s called\n", __func__);
#endif
	int taille_message=-1;
	unsigned char hlen;
	//recption du message envoyer par le client 
	
	sock->socket_state_receiver=wait_packet;
	if (sock->socket_type == nonlistening_server)
	{
		while (simptcp_extract_data(sock->in_buffer,buf)==0 ) 
		{
    		usleep(10);
		
		}

		lock_simptcp_socket(sock);
 		hlen= simptcp_get_head_len(sock->in_buffer);
		printf("DATA: %35s \n",((sock->in_buffer)+hlen));
		taille_message = simptcp_extract_data(sock->in_buffer,buf);
		simptcp_lprint_packet(sock->in_buffer);

		unlock_simptcp_socket(sock);
	}
  return taille_message;
}

/**
 * called when application calls close
 */
/*! \fn  int established_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	int sortie_du_sendto=-1;
	if (sock->socket_type == client) 
	{
		forger_pdu(sock,FIN);
		start_timer(sock, sock->timer_duration);
		sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, SIMPTCP_GHEADER_SIZE, 0, (struct sockaddr * )(&(sock->remote_udp)), sizeof(struct sockaddr_in)) ;  
	
		if(sortie_du_sendto==-1)
		{
			printf("----------------errreur lors de l'envoi du pdu fin coté client \n");
		}	
		else 
		{
			printf("----------------envoi du pdu fin coté client   \n");
			sock->socket_state = &(simptcp_entity.simptcp_socket_states->finwait1);
		}
	}
	else if(sock->socket_type == listening_server || sock->socket_type == nonlistening_server)
	{
			//si on reçoit une demande de fermeture de connexion côté serveur on envoi un ACK pour dire que l'on a bien reçu
			// cette demande et on passe en état closewait côté serveur 			
			
			while(simptcp_get_flags(sock->in_buffer)!=FIN)
			{
				usleep(10);
			}	
			forger_pdu(sock,ACK);
			sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, SIMPTCP_GHEADER_SIZE, 0, (struct sockaddr*) (&sock->remote_udp), sizeof(struct sockaddr_in)) ;
			simptcp_lprint_packet(sock->out_buffer);
			
			if(sortie_du_sendto==-1)
			{
				printf("----------------errreur lors de l'envoi du ACK fin coté serveur \n");
			}	
			else 
			{
				printf("----------------envoi du ACK fin coté serveur   \n");
				
			}
			printf("FIN DE CONNEXION AVEC LE CLIENT\n");
			//Libération du socket_fils après fermeture de la connexion 			
			
			free(simptcp_entity.simptcp_socket_descriptors[1]);
			sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
			
	}

	while (sock->socket_state != &simptcp_socket_states.closed){}
	return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{

#if  __DEBUG__
  printf("function %s called\n", __func__);
#endif


	//coté client : on traite la réception d'un ack , on passe donc en wait-message 
	int sortie_du_sendto;
	if (sock->socket_type == client) 
	{
		 if( simptcp_get_flags(buf) == ACK) 
		{
			
			if(sock->socket_state_sender == wait_ack && simptcp_get_ack_num(buf) == sock->next_seq_num)
			{
				printf("ACK reçu\n");
				simptcp_lprint_packet(buf);

      			lock_simptcp_socket(sock);
      			sock->next_ack_num = simptcp_get_seq_num(buf) + 1;
      			unlock_simptcp_socket(sock);
				stop_timer(sock);
      			// On passe dans l'etat WAIT_MESSAGE
     	 		sock->socket_state_sender = wait_message;
			}
		}
		else if ((simptcp_get_flags(buf) & ACK) == 0)
   		 {                 
				printf( "On a reçu un PDU mais ce n'est pas un ACK\n");
		}
		else
		{
				printf("On n'a pas de reçu de ACK\n");
		}
	}
	//coté serveur : on envoie le ack suite à la réception d'un message envoyé par le client 
	else if (sock->socket_type == listening_server || sock->socket_type == nonlistening_server) 
	{
			
			//si on reçoit une demande de fermeture de connexion côté serveur on envoi un ACK pour dire que l'on a bien reçu
			// cette demande et on passe en état closewait côté serveur 			
			if(simptcp_get_flags(buf)==FIN)
			{
				
				memcpy(sock->in_buffer, buf, simptcp_get_total_len(buf)); 				
			}
			//sinon on s'occupe de l'envoi d'un ACK pour la réception d'un message contenant des données			
			else
			{	
				sock->next_ack_num = simptcp_get_seq_num(buf) + 1;
				forger_pdu(sock,ACK);
				sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, SIMPTCP_GHEADER_SIZE, 0, (struct sockaddr*) (&sock->remote_udp), sizeof(struct sockaddr_in)) ;
				// on stocke le message dans le buffer du socket				
				memcpy(sock->in_buffer, buf, simptcp_get_total_len(buf)); 
				simptcp_lprint_packet(sock->out_buffer);
				if (sortie_du_sendto==-1)
				{
					printf("_________________erreur envoie ack \n");
				}
			}
	
	}
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

		//gestion d'un time out du au pdu des données 
	
		sock->next_ack_num=simptcp_get_seq_num(sock->out_buffer);				
		int sortie_du_sendto =libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sizeof(sock->out_buffer), 0, (struct sockaddr*) (&sock->remote_udp), sizeof(struct sockaddr_in));
		simptcp_lprint_packet(sock->out_buffer);
		start_timer(sock, sock->timer_duration);

}


/*********************************************************
 * closewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock,  struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int closewait_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * finwait1_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int finwait1_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
}

/**
 * called when application calls accept
 */
/*! \fn int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	
	
}

/**
 * called when application calls close
 */
/*! \fn  int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    
	return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

	//si on recoit un ack de la demande de fermeture de connexion de fin (du client ), on passe à l'état timewait et on lance le timer du timewait  
	if (simptcp_get_flags(buf) == ACK)
	{
		memcpy(sock->in_buffer, buf, simptcp_get_total_len(buf));
		stop_timer(sock);		
		printf("ACK reçu \n");
		simptcp_lprint_packet(sock->in_buffer);
		sock->socket_state = &(simptcp_entity.simptcp_socket_states->timewait);
		start_timer(sock, sock->timer_duration);
	}
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * finwait2_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "fainwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int finwait2_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * closing_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int closing_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * lastack_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int lastack_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * timewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */


/*! \fn int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
   
}

/**
 * called when application calls listen
 */
/*! \fn int timewait_simptcp_socket_state_passive_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param len taille en octet du message à transmettre 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv			sock->next_ack_num = simptcp_get_seq_num(buf) + 1;
 */
/*! \fn ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param [out] len taille en octet du message recu 
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{
  
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    
}

/**
 * called when application calls shutdown
 */
/*! \fn  int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	
	// Si l'on reçoit un paquet après la demande de fermeture de connexion on va les jeter à la poubelle 	
	if(simptcp_get_total_len(sock->in_buffer)!=0)
	{
		memcpy(sock->in_buffer, buf, simptcp_get_total_len(buf)); 
		free(sock->in_buffer);
		printf("Réception d'un paquet \n");
	}
	
		
	

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
	
// on a un timeout , on libere la socket cliente , et on passe dans l'état closed  
	printf("---------------- Fermeture de connection ---------------\n");
	free(sock);
	sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
	return 0;	
	
}

// TODO : rajouter fonction delete/remove simptcp_socket

