#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

const int RESOLVER_PORT = 18000;

const int MAX_DOMAINS = 1024;
const int MAX_DOMAIN_LENGTH = 32;

const int standart_dns_query_buffer_size = 512;

const int qname_start_byte_index = 13;
const int rdata_first_byte_index = 39;
const int rdata_second_byte_index = 40;

FILE *config_file_ptr;
const char *config_file_name = {"config.txt"};

void helper_printBuffer(char *buffer, int size) {
  printf("Buffer:");
  for (int i = 0; i < size; i++) {
    printf("%02X", (unsigned char)buffer[i]);
  }
  printf("\n");
}

void helper_printDNSAnswer(char *responseBuffer, int responseSize) {
  printf("Received %d bytes from DNS server\n", (int)responseSize);
  printf("\n");

  printf("ID: %02X%02X\n", (unsigned char)responseBuffer[0],
         (unsigned char)responseBuffer[1]);
  printf("Flags: %02X%02X\n", (unsigned char)responseBuffer[2],
         (unsigned char)responseBuffer[3]);
  printf("Question count: %02X%02X\n", (unsigned char)responseBuffer[4],
         (unsigned char)responseBuffer[5]);
  printf("Answer count: %02X%02X\n", (unsigned char)responseBuffer[6],
         (unsigned char)responseBuffer[7]);
  printf("Name server count: %02X%02X\n", (unsigned char)responseBuffer[8],
         (unsigned char)responseBuffer[9]);
  printf("Add resources count: %02X%02X\n", (unsigned char)responseBuffer[10],
         (unsigned char)responseBuffer[11]);

  int parser_index = 12;
  int qname_bytes = 0;
  printf("QNAME:\n");
  while (responseBuffer[parser_index] != 0) {
    printf(" %02X", (unsigned char)responseBuffer[parser_index]);
    parser_index++;
    qname_bytes++;
  }
  printf("\n");

  printf("QTYPE %02X%02X\n", (unsigned char)responseBuffer[parser_index + 1],
         (unsigned char)responseBuffer[parser_index + 2]);
  printf("QCLASS %02X%02X\n", (unsigned char)responseBuffer[parser_index + 3],
         (unsigned char)responseBuffer[parser_index + 4]);

  int ans_parser_index = parser_index + 5;
  printf("ANAME:\n");
  while (responseBuffer[ans_parser_index] != 0) {
    printf(" %02X", (unsigned char)responseBuffer[ans_parser_index]);
    ans_parser_index++;
  }
  printf("\n");

  printf("ans_parser_index: %d\n", ans_parser_index);
  printf("RRTYPE %02X%02X\n", (unsigned char)responseBuffer[ans_parser_index],
         (unsigned char)responseBuffer[ans_parser_index + 1]);
  printf("RRCLASS %02X%02X\n",
         (unsigned char)responseBuffer[ans_parser_index + 2],
         (unsigned char)responseBuffer[ans_parser_index + 3]);
  printf("TTL %02X%02X%02X%02X\n",
         (unsigned char)responseBuffer[ans_parser_index + 4],
         (unsigned char)responseBuffer[ans_parser_index + 5],
         (unsigned char)responseBuffer[ans_parser_index + 6],
         (unsigned char)responseBuffer[ans_parser_index + 7]);
  printf("RDLENGTH %02X%02X\n",
         (unsigned char)responseBuffer[ans_parser_index + 8],
         (unsigned char)responseBuffer[ans_parser_index + 9]);

  int rdata_lenght = 0;

  printf("rdata_lenght first byte%d\n", ans_parser_index + 8);
  rdata_lenght = responseBuffer[ans_parser_index + 8] * 256 +
                 responseBuffer[ans_parser_index + 9];

  printf("%d\n", rdata_lenght);

  for (int i = 0; i < rdata_lenght; i++) {
    printf(" %02X", (unsigned char)responseBuffer[ans_parser_index + 10 + i]);
  }
  printf("\n");

  for (int i = 0; i < rdata_lenght; i++) {
    printf(" %d", (uint8_t)responseBuffer[ans_parser_index + 10 + i]);
  }
  printf("\n");
}

void helper_printBlackList(char (*blacklist)[MAX_DOMAIN_LENGTH], int size) {
  printf("Size of a blacklist: %d\n", size);
  printf("Black list:\n");
  for (int i = 0; i < size; i++) {
    for (int j = 0; j < MAX_DOMAIN_LENGTH; j++) {
      if (blacklist[i][j] != '\0') {
        printf("%c", blacklist[i][j]);
      } else {
        break;
      }
    }
    printf("\n");
  }
}

int parseConfigFile(char (*blacklist)[MAX_DOMAIN_LENGTH],
                    char *resolver_dns_server) {
  int black_list_size = 0;
  config_file_ptr = fopen("config.txt", "r");

  if (config_file_ptr == NULL) {
    printf("File could not be opened.\n");
    return;
  }

  char dns_server_address[MAX_DOMAIN_LENGTH];
  char buffer[MAX_DOMAIN_LENGTH];

  fgets(dns_server_address, sizeof(dns_server_address), config_file_ptr);

  strcpy(resolver_dns_server, dns_server_address);

  int list_iterator = 0;
  while (fgets(buffer, sizeof(buffer), config_file_ptr) != NULL &&
         list_iterator < MAX_DOMAINS) {
    buffer[strcspn(buffer, "\n")] = 0; // Removes the newline character
    strncpy(blacklist[list_iterator], buffer, strlen(buffer));
    list_iterator++;
  }

  black_list_size = list_iterator;

  fclose(config_file_ptr);

  return black_list_size;
}

void printSiteIPAdress(char *responseBuffer, int responseSize) {
  int rdata_lenght = responseBuffer[rdata_first_byte_index] * 256 +
                     responseBuffer[rdata_second_byte_index];

  int i = 0;
  printf("IP adress for your requst: ");
  while (responseBuffer[qname_start_byte_index + i] != 0) {
    if (responseBuffer[qname_start_byte_index + i] == 3) {
      printf(".");
      i++;
    } else {
      printf("%c", responseBuffer[qname_start_byte_index + i]);
      i++;
    }
  }
  printf(" is ");

  for (int i = 0; i < rdata_lenght; i++) {
    printf("%d", (uint8_t)responseBuffer[rdata_second_byte_index + 1 + i]);
    if (i != rdata_lenght - 1) {
      printf(".");
    }
  }
  printf("\n");
}

char *convertQnameToChar(char *buffer, int buffer_size) {
  int i = 0;
  int qname_size = 0;
  char *qname;

  while (buffer[qname_start_byte_index + i] != 0) {
    i++;
  }

  qname_size = i;
  qname = (char *)malloc(sizeof(char) * MAX_DOMAIN_LENGTH);
  for (int i = 0; i < MAX_DOMAIN_LENGTH; i++) {
    qname[i] = 0;
  }

  for (int i = 0; i < qname_size; i++) {
    if (buffer[qname_start_byte_index + i] == 3) {
      qname[i] = '.';
    } else {
      qname[i] = buffer[qname_start_byte_index + i];
    }
  }

  return qname;
}

bool isQueryNameBlocked(char *buffer, int buffer_size,
                        char (*blacklist)[MAX_DOMAIN_LENGTH],
                        int blacklist_size) {
  char *qname = convertQnameToChar(buffer, buffer_size);
  for (int i = 0; i < blacklist_size; i++) {
    int counter = 0;
    for (int j = 0; j < MAX_DOMAIN_LENGTH; j++) {
      if (qname[j] == blacklist[i][j]) {
        counter++;
      }
    }
    if (counter == MAX_DOMAIN_LENGTH) {
      return true;
    }
  }

  free(qname);
  return false;
}

void buildBlockedDNSResponse(char *request_buffer) {
  request_buffer[2] = 81;
  request_buffer[3] = 83;
}

void sendDNSQuerryToParentDNSServer(int sock, char *buffer,
                                    char *resolver_dns_server,
                                    struct sockaddr_in sa, ssize_t recsize) {

  struct sockaddr_in parent_dns_server;

  parent_dns_server.sin_family = AF_INET;
  parent_dns_server.sin_port = htons(53);
  parent_dns_server.sin_addr.s_addr = inet_addr(resolver_dns_server);

  // Send the DNS query using UDP
  sendto(sock, buffer, recsize, 0, (struct sockaddr *)&parent_dns_server,
         sizeof(parent_dns_server));

  char responseBuffer[standart_dns_query_buffer_size];

  // Receive the DNS response from the DNS server
  ssize_t responseSize =
      recvfrom(sock, responseBuffer, sizeof(responseBuffer), 0,
               (struct sockaddr *)&parent_dns_server, &parent_dns_server);

  helper_printBuffer(responseBuffer, responseSize);

  if (responseSize < 0) {
    perror("Error: recvfrom failed");
    exit(EXIT_FAILURE);
  } else if (responseSize > standart_dns_query_buffer_size) {
    perror("Error: response from DNS server is bigger than 512 bytes ");
  } else {
    sendto(sock, responseBuffer, recsize, 0, (struct sockaddr *)&sa,
           sizeof(sa));
  }

  printSiteIPAdress(responseBuffer, responseSize);
}

int main(void) {
  char black_list[MAX_DOMAINS][MAX_DOMAIN_LENGTH];
  char resolver_dns_server[MAX_DOMAIN_LENGTH];
  char standart_answer[MAX_DOMAIN_LENGTH];

  int black_list_size;

  // Initialize the blacklist array with null characters
  for (int i = 0; i < MAX_DOMAINS; i++) {
    memset(black_list[i], 0, sizeof(black_list[i]));
  }

  black_list_size = parseConfigFile(black_list, resolver_dns_server);

  int sock;
  struct sockaddr_in sa;
  socklen_t fromlen;

  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(RESOLVER_PORT);
  fromlen = sizeof sa;

  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (bind(sock, (struct sockaddr *)&sa, sizeof sa) == -1) {
    perror("Error: bind failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  for (;;) {
    ssize_t recsize;
    char buffer[1024];

    // Receive DNS query from client
    recsize = recvfrom(sock, (void *)buffer, sizeof buffer, 0,
                       (struct sockaddr *)&sa, &fromlen);

    if (recsize < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    helper_printBlackList(black_list, black_list_size);
    if (isQueryNameBlocked(buffer, recsize, black_list, black_list_size)) {
      buildBlockedDNSResponse(buffer);
      sendto(sock, buffer, recsize, 0, (struct sockaddr *)&sa, sizeof(sa));
    } else {
      sendDNSQuerryToParentDNSServer(sock, buffer, resolver_dns_server, sa,
                                     recsize);
    }
  }

  free(config_file_ptr);
  free(config_file_name);
  close(sock);
}
