/* Projekt do predmetu ISA
   Nazev : Monitorovani IPTV vysilani
   Vytvoril : Jakub Mensik */

#include <arpa/inet.h>
#include <err.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_IP_LENGHT 45
#define MAX_SOURCE_IPS 50

typedef struct tElem {
    struct tElem *ptr;              // ukazatel na dalsi prvek seznamu
    char *destIP;                   // destination IP
    char *sourceIP;                 // source IP
    char *type;                     // typ ES - audio/video/unknown
    int pid;                        // PID
    int counter;                    // pocet MPEG bloku v casovem intervalu pro vypis
    int isDone;                     // kontrolka, 0 pokud prvek neni vypsan, 1 pokud je
    float sum;                      // soucet jitteru, pozdeji se vydeli poctem udpPacketu pro prumerny jitter
    int controlJitter;              // kontrlka, jestli se ma pro dany prvek jitter pocitat
    float peakJitter;               // nejvyssi jitter
    struct timeval lastTime;        // cas v ms posledniho packetu
    int udpCounter;                 // pocet udp packetu, pro vypocet jitteru
    int lastCC;                     // posledni PID CC
    int outOfSync;                  // pocet chybejicich packetu za vterinu
} *tElemPtr;                   

typedef struct { 
    tElemPtr Act;                   // ukazatel na aktivni prvek
    tElemPtr First;                 // ukazatel na prvni prvek seznamu
} tList;

// podrobny popis funkci u jednotlivych definic
// HLAVNI FUNKCE
void Start(int*, char**);
void ProcessPacket(unsigned char* , int, int*, char**);
int ProcessMPEG(unsigned char*, int, char*, char*);

// POMOCNE FUNKCE
void HexToBinary(char*, int);
int Power(int, int);
void Error(char*);
float TimeDifferenceMS(struct timeval, struct timeval);

// FUNKCE PRO PRACI SE SEZNAMEM
void InitList(tList*);
void DisposeList(tList*);
void First (tList*);
int CheckList(tList*, char*, char*, int);
void InsertFirst (tList*, char*, char*, char*, int);
void IncrementElem(tList*, char *, char *, int, int);
void NullList(tList*);
void AddJitter(tList*, char *, char *, int);
void CountJitter(tList*);
void ChangeJitter(tList*, char *, char *, int);
void PrintDestIP(tList*, char*);
void PrintSourceIP(tList*, char*, char*);

int okIpCounter = 0;                    // pocet spravnych ip adres na vstupu
time_t seconds;                         // drzi cas posledniho vypisu
char *bits;                             // hlavicka MPEG bloku ve dvojkove soustave
tList LIST;                             // seznam pro ukladani destIP, sourceIP, PID a potrebnych dat
struct timeval t;                       // structura ktera drzi cas v ms pro vypocet jitteru

// funkce vytvori pole pro ukladani platnych ip adres z argumentu,
// dale se do pole ukladaji velikosti udp packetu, jejich pocet a
// pocet mpeg packetu
// dale je tam cool GOTO smycka, ktera se pripoji do vsech platnych
// zadanych multicastovych skupin, pak se zavola funkce pro prijimani packetu
int main(int argc, char *argv[]) {

    int fd;                 
    struct ip_mreq mreq;       
    int argcCounter=1;     

    // counters, names, dataSize, udpCounter
    int ipInfo[argc*5];

    if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) 
        Error("nelze vytvorit socket.");

    ARGS:

    mreq.imr_multiaddr.s_addr=inet_addr(argv[argcCounter]); 
    mreq.imr_interface.s_addr=htonl(INADDR_ANY);  

    if (setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0) {
        Error("nelze se pripojit do multicast skupiny");
    } else {
        ipInfo[okIpCounter*5] = argcCounter;
        ipInfo[okIpCounter*5+1] = 0;
        ipInfo[okIpCounter*5+2] = 0;
        ipInfo[okIpCounter*5+3] = 0;
        ipInfo[okIpCounter*5+4] = 0;
        okIpCounter++;
    }
  
    argcCounter++;
    if (argc != argcCounter) goto ARGS;

    if (okIpCounter>0) {
        Start(ipInfo, argv);
    } else {
        Error("Nepodarilo se pripojit k zadnemu vysilani...");
    }    
     
    close(fd);
    DisposeList(&LIST);
    exit(0);
}

// funkce vytvori buffer pro maximalni moznou velikost packetu,
// vytvori raw socket, nastavi aktualni cas, pak v nekonecne smycce
// prijmi pres recvfrom packety a vola funkci pro jejich zpracovani
void Start(int* ipInfo, char *argv[]) {
    int sock_raw;
    int saddr_size , data_size;
    struct sockaddr saddr;
     
    unsigned char *buffer = (unsigned char *)malloc(65536); 
    if(buffer == NULL) Error("chyba allokace pameti.");

    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
    if(sock_raw < 0) Error("nelze vytvorit raw socket.");

    seconds = time(NULL);

    // nekonecna smycka pro prijimani packetu
    while(420) {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
        if(data_size < 0) {
            Error("selhala funkce recvfrom.");
        }

        gettimeofday(&t, 0);
        ProcessPacket(buffer, data_size, ipInfo, argv);
    }
    free(buffer);
    close(sock_raw);
}

// funkce zpracuje ip header, podiva se jestli jde o udp packet, pokud ano, zpracuje ho
// dale funkce kontroluju cas, tzn. jestli uz ubehla vterina od posledniho vypisu, pokud
// ano, vypise data 
void ProcessPacket(unsigned char* buffer, int size, int* ipInfo, char *argv[]) {

    int i = 0;
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;

    // zpracovani destIP a sourceIP
    struct iphdr *iph = (struct iphdr*)buffer;
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char *destinationIP = malloc(sizeof(inet_ntoa(dest.sin_addr)));
    if(destinationIP == NULL) Error("chyba allokace pameti.");
    strcpy(destinationIP, inet_ntoa(dest.sin_addr));
    char *sourceIP = malloc(sizeof(inet_ntoa(source.sin_addr)));
    if(sourceIP == NULL) Error("chyba allokace pameti.");
    strcpy(sourceIP, inet_ntoa(source.sin_addr));

    // kontrola jestli jde o udp packet
    if (iph->protocol == 17) {

        LABEL:

        if (strcmp(destinationIP, argv[ipInfo[i*5]]) == 0) {
            ipInfo[i*5+1]++;
            ipInfo[i*5+2] += ntohs(iph->tot_len);
            ipInfo[i*5+3] += 1;
            //PrintUdpPacket(buffer, size);

            ipInfo[i*5+4] += ProcessMPEG(buffer + iphdrlen + sizeof udph, (size - sizeof udph - iphdrlen), destinationIP, sourceIP);
        } else {
            i++;
            if (i < okIpCounter) {
                goto LABEL;
            }
        }
    }
    free(destinationIP);
    free(sourceIP);

    // kontrola casu
    if (seconds != time(NULL)) {
        printf("\033[2J");
        printf("Multicast groups statistics:\n\t\t\tBandwidth\tUDP packets\tMPEG-TS blocks\n");
        for (i=0; i<okIpCounter; i++) {
            double tmpCounter = (double) ipInfo[i*5+2]*8;
            int y = 0;
            char *bytes;
            for (y=0; tmpCounter > 1000; y++) {
                tmpCounter = tmpCounter / 1000;
            }
            if (y == 0) {
                bytes = "Bps";
            } else if (y == 1) {
                bytes = "Kbps";
            } else if (y == 2) {
                bytes = "Mbps";
            } else if (y == 3) {
                bytes = "Gbps";
            }
            printf("%s\t\t%.2f %s\t%d\t\t%d\n", argv[ipInfo[i*5]], tmpCounter, bytes, ipInfo[i*5+3], ipInfo[i*5+4]);
            ipInfo[i*5+2] = 0;
        }
        printf("\nElementary streams statistics:\n");
        for (i=0; i<okIpCounter; i++) {
            PrintDestIP(&LIST, argv[ipInfo[i*5]]);
        }

        NullList(&LIST);
        printf("\n\n\n\n");
        seconds = time(NULL);
    }
}

// tato funkce zpracuje hlavicku MPEG bloku, tzn. ma za ukol najit zacatky bloku,
// podivat se na PUSI, pokud je nastaven na 1, tak zpracovat PES a pripadne ulozit
// novy PID a typ do seznamu, dale ma za ukol vytahnout z MPEG bloku PID, PID CC
int ProcessMPEG(unsigned char* data , int size, char *destIP, char *sourceIP) {

    char tmp[3];
    char type[8];
    char *str;
    int i=0;
    int j=0;
    int c;
    int pid = 0;
    int CC = 0;
    int mpegCounter = 0;

    while (i<size) {
        if (i%188 == 0) {
            sprintf(tmp, "%02X", (unsigned int)data[i]);
            pid = 0;

            // pokud je to zacatek MPEG bloku
            if (!strcmp(tmp, "47")) {
                mpegCounter++;
                str = malloc(sizeof("0000000000000000"));
                if(str == NULL) Error("chyba allokace pameti.");
                for (j=i+1; j<i+5; j++) {
                    sprintf(tmp, "%02X", (unsigned int)data[j]);
                    strcat(str,tmp);
                }

                HexToBinary(str, 4);

                for (j=3; j<16; j++) {
                    c = bits[j];
                    if (c == 49) {
                        pid += Power(2, 12-(j-3));
                    }
                }

                // kontrola PUSI
                c = bits[1];
                if (c == 49) { 
                    free(str);
                    str = malloc(sizeof("FFFFFF"));
                    if(str == NULL) Error("chyba allokace pameti.");
                    for (j=i+4; j<i+7; j++) { 
                        sprintf(tmp, "%02X", (unsigned int)data[j]); 
                        strcat(str,tmp); 
                    }

                    // kontrola jestli se jedna opravdu o PES
                    if (!strcmp(str, "000001")) {
                        free(str);
                        str = malloc(sizeof("FF"));
                        if(str == NULL) Error("chyba allokace pameti.");
                        sprintf(str, "%02X", (unsigned int)data[i+7]); 
                        c = str[0];

                        // urceni typu
                        if (c == 67 || c == 68) {
                            sprintf(type, "%s", "audio");
                        } else if (c == 69) {
                            sprintf(type, "%s", "video");
                        } else {
                            sprintf(type, "%s", "unknown");
                        }

                        // vlozi prvek do seznamu pokud tam jeste neni
                        if (!CheckList(&LIST, destIP, sourceIP, pid)) {
                            InsertFirst(&LIST, destIP, sourceIP, type, pid);
                        }
                    }
                    free(bits);
                }

                // urci PID CC
                sprintf(tmp, "%02X", (unsigned int)data[i+3]);
                c = tmp[1];
                if (c == 49) CC=1;
                else if (c == 50) CC=2;
                else if (c == 51) CC=3;
                else if (c == 52) CC=4;
                else if (c == 53) CC=5;
                else if (c == 54) CC=6;
                else if (c == 55) CC=7;
                else if (c == 56) CC=8;
                else if (c == 57) CC=9;
                else if (c == 65) CC=10;
                else if (c == 66) CC=11;
                else if (c == 67) CC=12;
                else if (c == 68) CC=13;
                else if (c == 69) CC=14;
                else if (c == 70) CC=15;

                // zvysi pocet MPEG bloku pro dany pid
                IncrementElem(&LIST, destIP, sourceIP, pid, CC);
                AddJitter(&LIST, destIP, sourceIP, pid);

                CC = 0;
                free(str);
            }
        }
        i++;
    }

    CountJitter(&LIST);

    return mpegCounter;    
}

// prevede hlavicku MPEG bloku z sestnactkove soustavy do dvojkove
void HexToBinary(char *hex, int size) {

    int c;
    char binary[17] = "0000000000000000";

    int i;
    for (i=0; i<size; i++) { 
        c = hex[i]; 
        if (c == 49) binary[i*4+3] = '1';
        else if (c == 50) binary[i*4+2] = '1';
        else if (c == 51) { binary[i*4+2] = '1'; binary[i*4+3] = '1'; }
        else if (c == 52) binary[i*4+1] = '1';
        else if (c == 53) { binary[i*4+1] = '1'; binary[i*4+3] = '1'; }
        else if (c == 54) { binary[i*4+1] = '1'; binary[i*4+2] = '1'; }
        else if (c == 55) { binary[i*4+1] = '1'; binary[i*4+2] = '1'; binary[i*4+3] = '1'; }
        else if (c == 56) binary[i*4] = '1';
        else if (c == 57) { binary[i*4] = '1'; binary[i*4+3] = '1'; }
        else if (c == 65) { binary[i*4] = '1'; binary[i*4+2] = '1'; }
        else if (c == 66) { binary[i*4] = '1'; binary[i*4+2] = '1'; binary[i*4+3] = '1'; }
        else if (c == 67) { binary[i*4] = '1'; binary[i*4+1] = '1'; }
        else if (c == 68) { binary[i*4] = '1'; binary[i*4+1] = '1'; binary[i*4+3] = '1'; }
        else if (c == 69) { binary[i*4] = '1'; binary[i*4+1] = '1'; binary[i*4+2] = '1'; }
        else if (c == 70) { binary[i*4] = '1'; binary[i*4+1] = '1'; binary[i*4+2] = '1';  binary[i*4+3] = '1'; }
    }

    bits = malloc(sizeof(binary));
    if(bits == NULL) Error("chyba allokace pameti.");
    strcpy(bits, binary);
}

// funkce pro vypocet druhe mocniny
int Power(int base, int degree) {

    int i;
    int tmp = base;

    if (degree == 0) return 1;
    if (degree == 1) return base;

    for (i=1; i<degree; i++) {
        tmp *= base;
    }

    return tmp;
}

// inicializace seznamu
void InitList(tList *L) {    
    L->Act = NULL;
    L->First = NULL;
}

// smazani seznamu
void DisposeList(tList *L) {
    tElemPtr item;
    while (L->First != NULL) {
        item = L->First;
        L->First = L->First->ptr;
        free(item->destIP);
        free(item->sourceIP);
        free(item->type);
        free(item);
    }
}

// vlozeni prvku seznamu na jeho zacatek
void InsertFirst (tList *L, char *destIP, char *sourceIP, char *type, int pid) { 
    struct tElem *newItem;
    newItem = malloc(sizeof(struct tElem));
    if(newItem == NULL) Error("chyba allokace pameti.");
    newItem->ptr = L->First;
    newItem->destIP = malloc(sizeof(destIP));
    if(newItem->destIP == NULL) Error("chyba allokace pameti.");
    strcpy(newItem->destIP, destIP);
    newItem->sourceIP = malloc(sizeof(sourceIP));
    if(newItem->sourceIP == NULL) Error("chyba allokace pameti.");
    strcpy(newItem->sourceIP, sourceIP);
    newItem->type = malloc(sizeof(type));
    if(newItem->type == NULL) Error("chyba allokace pameti.");
    strcpy(newItem->type, type);
    newItem->pid = pid;
    newItem->counter = 0;
    newItem->isDone = 0;
    newItem->udpCounter = 0;
    newItem->sum = 0;
    newItem->lastTime.tv_sec = 0;
    newItem->controlJitter = 0;
    newItem->peakJitter = 0;
    newItem->lastCC = 0;
    newItem->outOfSync = 0;
    L->First = newItem;
}

// funkce projede seznam a podiva se, jestli uz seznam neobsahuje
// prvek s danou destIP, source IP a PID
int CheckList(tList *L, char *destIP, char *sourceIP, int pid) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        if (!strcmp(item->destIP, destIP) &&
            !strcmp(item->sourceIP, sourceIP) &&
            item->pid == pid) {
            return 1;
        }
    }
    First(L);
    return 0;
}

// funkce zvysi pocet mpeg packetu s danou destIP, sourceIP a PID, dale ma 
// za ukol zkontrolovat navaznost packetu, pokud na sebe packety nenavazuji,
// ulozi si pocet chybejicich mpeg bloku, coz se pozdeji vyuzije pro vypocet
// out of sync
void IncrementElem(tList *L, char *destIP, char *sourceIP, int pid, int CC) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        if (!strcmp(destIP, item->destIP) &&
            !strcmp(sourceIP, item->sourceIP) &&
            pid == item->pid) {
            item->counter++;
            int diff = 0;
            if (item->lastCC+1 == CC || (item->lastCC==15 && CC==0)) {
                item->lastCC = CC;
            } else {
                while (item->lastCC != CC) {
                    item->lastCC++;
                    if (item->lastCC == 16) item->lastCC = 0;
                    diff++;
                }
                item->outOfSync += diff;
                if (diff > 1) item->outOfSync--;
            }
            First(L);
            break;
        }
    }
}

// funkce nastavi prvek seznamu tak, aby se spocital jitter
void AddJitter(tList *L, char *destIP, char *sourceIP, int pid) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        if (!strcmp(destIP, item->destIP) &&
            !strcmp(sourceIP, item->sourceIP) &&
            pid == item->pid) {
            item->controlJitter = 1;
            First(L);
            break;
        }
    }
}

// funkce ma za ukol spocitat delay mezi aktualne zpracovavanym packetem
// a minulym packetem, hodnota v ms se ulozi do promenne a pozdeji se
// vypocita avg jitter, dale funkce kontroluje a uklada peak jitter
void CountJitter(tList* L) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        if (item->controlJitter)
            if (item->lastTime.tv_sec == 0) {
                item->lastTime = t;
            } else {
                float diff = TimeDifferenceMS(item->lastTime, t);
                item->sum += diff;
                item->lastTime = t;
                if (item->peakJitter < diff) item->peakJitter = diff;
            }
            item->udpCounter++;
            item->controlJitter = 0;
    }
    First(L);
}

// funkce ma za ukol po kazdem vypisu vynulovat nektere prvky,
// ktere merime za urcity cas (1s)
void NullList(tList *L) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        item->counter = 0;
        item->isDone = 0;
        item->sum = 0;
        item->lastTime.tv_sec = 0;
        item->udpCounter = 0;
        item->lastCC = 0;
        item->outOfSync = 0;
    }
    First(L);
}

// funkce ma zadaou destIP, projede seznam, kdyz narazi na danou destIP,
// zavola dalsi funkci se sourceIP, ktera projede seznam a vypise hodnoty 
void PrintDestIP(tList *L, char *destIP) {
    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        if (item->isDone == 0 && !strcmp(item->destIP, destIP)) {
            printf("%s, source %s\n", destIP, item->sourceIP);
            printf("  PID\ttype\tbandwidth\tout of sync\tavg jitter\tpeak jitter\n");
            PrintSourceIP(L, destIP, item->sourceIP);
            First(L);
        } else {
            L->Act = L->Act->ptr;
        }
    }
}

// tato funkce ma na vstupu destIP a sourceIP, projede seznam a vypise
// prvky s temito hodnotami a nastavi promennou isDone na 1, cimz rika, ze 
// tento prvek je jiz vypsan, dale funkce pocita bandwidth, jitter, out of sync
void PrintSourceIP(tList *L, char *destIP, char *sourceIP) {

    float jitter = 0;
    float oos = 0;
    char *bytes;

    First(L);
    tElemPtr item;
    while (L->Act != NULL) {
        item = L->Act;
        L->Act = L->Act->ptr;
        if (!strcmp(item->destIP, destIP) &&
            !strcmp(item->sourceIP, sourceIP) &&
            item->isDone == 0) {
            double tmpCounter = (double) item->counter*188*8;
            int y = 0; 
            
            for (y=0; tmpCounter > 1000; y++) {
                tmpCounter = tmpCounter / 1000;
            }
            if (y == 0) {
                bytes = "Bps";
            } else if (y == 1) {
                bytes = "Kbps";
            } else if (y == 2) {
                bytes = "Mbps";
            } else if (y == 3) {
                bytes = "Gbps";
            }

            if (item->counter > 0) oos = ( ( (float)item->outOfSync) / ( (float)item->counter + (float)item->outOfSync) ) * 100.0;
            else oos = 0.0;
            if (oos > 100) oos = 100;

            if (item->udpCounter > 0) jitter = item->sum / item->udpCounter;

            printf("  %d\t%s\t%.2f %s\t %.02f\t\t%.02f\t\t%.02f\n", item->pid, item->type, tmpCounter, bytes, oos, jitter, item->peakJitter);
            item->isDone = 1;
        }
    }
    First(L);
}

// vrati rozdil dvou casu v ms
float TimeDifferenceMS(struct timeval t0, struct timeval t1) {
    return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

// zmeni aktualni prvek seznamu na prvni prvek
void First (tList *L) {
    L->Act = L->First;
}

// vypise chybovou hlasku
void Error(char *msg) {
    fprintf(stderr, "Error - %s\n", msg);
}