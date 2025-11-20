#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>

int main() {
    int sockfd;
    struct sockaddr_ll sll;
    struct ifreq ifr;

    // criaçao do raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // identifica  a interface tun0
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    // conceta a ela
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        exit(1);
    }

    // captura de grames
    unsigned char buffer[65536];

    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len <= 0) continue;

        // envia o frame bruto para o stdout
        int n = htonl(len);
        fwrite(&n, sizeof(n), 1, stdout);  // tamanho
        fwrite(buffer, 1, len, stdout);        // frame
        fflush(stdout);
    }

    close(sockfd);
    return 0;
}
