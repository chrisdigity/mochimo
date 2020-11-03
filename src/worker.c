/* worker.c
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * The Mochimo Project Worker Software
 * This file builds a worker.
 *
 * Date: 28 April 2019
*/

#define VERSIONSTR "Version 0.9.7"

#define VEOK           0   /* No error                    */
#define VERROR         1   /* General error               */
#define VEBAD          2   /* client was bad              */
#define VEBAD2         3   /* client was naughty          */
#define VETIMEOUT    (-1)  /* socket timeout              */

/* Cross Platform Definitions */
#ifdef WIN32
/* Nullify non-windows functions (temporary)
 * Please let the c gods forgive me... */
#define kill(pid, opts)             (-1)
#define waitpid(pid, status, opts)  (-1)
typedef int pid_t;
#endif

/* Core includes */
#include <inttypes.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "config.h"
#include "sock.h"     /* BSD sockets */
#include "types.h"
#include "crypto/hash/cpu/sha256.h"

/* Prototypes */
#include "proto.h"

/* Overrides */
int pinklist(word32 ip) { return VEOK; }
int epinklist(word32 ip) { return VEOK; }
void stop_mirror(void) { /* do nothing */ }

/* Include global data */
#include "data.c"          /* System wide globals              */
byte Interval;             /* get_work() poll interval seconds */

/* Support functions   */
#include "error.c"         /* error logging etc.               */
#include "add64.c"         /* 64-bit assist                    */
#include "crypto/crc16.c"
#include "crypto/crc32.c"  /* for mirroring                    */
#include "rand.c"          /* fast random numbers              */

/* Server control      */
#include "util.c"        /* cross platform support functions */
#include "sock.c"          /* inet utilities                   */
#include "connect.c"       /* make outgoing connection         */
#include "call.c"          /* callserver() and friends         */
#include "str2ip.c"

/* Mining algorithm */
#include "algo/peach/peach.c"
#ifdef CUDANODE
#include "algo/peach/cuda_peach.h"
#endif

/**
 * Clear run flag, Running on SIGTERM */
void sigterm(int sig)
{
   signal(SIGTERM, sigterm);
   Running = 0;
}

/* Modified sendtx() & send_op() from gettx.c
 * Send packet: set advertised fields and crc16.
 * Returns VEOK on success, else VERROR.
 */
int sendtx(NODE *np)
{
   int count, len;
   time_t timeout;
   byte *buff;

   np->tx.version[0] = PVERSION;
   np->tx.version[1] = Cbits;
   put16(np->tx.network, TXNETWORK);
   put16(np->tx.trailer, TXEOT);

   put16(np->tx.id1, np->id1);
   put16(np->tx.id2, np->id2);
   /*
   put64(np->tx.cblock, Cblocknum);
   memcpy(np->tx.cblockhash, Cblockhash, HASHLEN);
   */
   memcpy(np->tx.pblockhash, Userhash, HASHLEN);
   memcpy(np->tx.weight, Weight, HASHLEN);
   memcpy(np->tx.chg_addr, Maddr, TXADDRLEN);
   crctx(&np->tx);
   count = send(np->sd, TXBUFF(&np->tx), TXBUFFLEN, 0);
   if(count == TXBUFFLEN) return VEOK;
   /* --- v20 retry */
   if(Trace) plog("sendtx(): send() retry...");
   timeout = time(NULL) + 10;
   for(len = TXBUFFLEN, buff = TXBUFF(&np->tx); ; ) {
      if(count == 0) break;
      if(count > 0) { buff += count; len -= count; }
      else {
         if(errno != EWOULDBLOCK || time(NULL) >= timeout) break;
      }
      count = send(np->sd, buff, len, 0);
      if(count == len) return VEOK;
   }
   /* --- v20 end */
   Nsenderr++;
   if(Trace)
      plog("send() error: count = %d  errno = %d", count, errno);
   return VERROR;
}  /* end sendtx() */

int send_op(NODE *np, int opcode)
{
   put16(np->tx.opcode, opcode);
   return sendtx(np);
}

/**
 * Initialize miner and allocate memory where appropriate */
int init_miner(BTRAILER *bt, byte diff)
{
   int initGPU;

#ifdef CUDANODE
   /* Initialize CUDA specific memory allocations
    * and check for obvious errors */
   initGPU = -1;
   initGPU = init_cuda_peach(diff, (byte *) bt, &Running);
   if(initGPU==-1) {
      splog(RED, "Error: Cuda initialization failed.\n");
      free_cuda_peach();
      return VERROR;
   }
   if(initGPU<1 || initGPU>64) {
      splog(RED, "Error: Unsupported number of GPUs detected -> %d\n", initGPU);
      free_cuda_peach();
      return VERROR;
   }
#endif

   return VEOK;
} /* end init_miner() */

/**
 * Update miner data where appropriate */
int update_miner(BTRAILER *bt, byte diff)
{
   int updateGPU;

#ifdef CUDANODE
   /* Initialize CUDA specific memory allocations
    * and check for obvious errors */
   updateGPU = -1;
   updateGPU = update_cuda_peach(diff, (byte *) bt);
   if(updateGPU==-1) {
      splog(RED, "\nError: Cuda update failed... ");
      return VERROR;
   }
#endif

   return VEOK;
} /* end update_miner() */

/**
 * Un-Initialize miner and free memory allocations where appropriate */
int uninit_miner()
{
#ifdef CUDANODE
   /* Free allocated memory on CUDA devices */
   free_cuda_peach();
#endif

   return VEOK;
} /* end uninit_miner() */

/**
 * Get work from a node/pool.
 * Protocol...
 *    Perform Mochimo Network three-way handshake.
 *    Send OP code "Send Block" (OP_SEND_BL).
 *    Receive data into NODE pointer.
 * Data Received...
 *    tx,              TX struct containing the received data.
 *    tx->len,         16 bit unsigned integer (little endian) containing the
 *                     length (in bytes) of data stored in tx->src_addr.
 *    tx->src_addr,    byte array containing at least 164 bytes of data...
 *       byte 0-159,   ... 160 byte block trailer to be used for mining.
 *       byte 160-163, ... 32 bit (little endian) host difficulty.
 *       byte 164-178, ... 16 byte array of random data
 *                         (intended use; avoid duplicate work between workers)
 *    } 
 * Worker Function... */
int get_work(NODE *np)
{
   int ecode = 0;
   int rxstatus = 0;

   /* connect using Mochimo handshake */
   if(callserver(np, Peerip) != VEOK) {
      splog(RED, "Error: Could not connect to host\n");
      return VERROR;
   }

   /* request work */
   if(send_op(np, OP_SEND_BL) != VEOK) ecode = 1;
   if(!ecode && (rxstatus = rx2(np, 1, 10)) != VEOK) ecode = 2;
   if(!ecode && get16(np->tx.opcode) != OP_SEND_BL) ecode = 3;

   closesocket(np->sd);
   if(ecode) {
      if(rxstatus == VETIMEOUT)
         splog(YELLOW, "Warning: Host connection TIMEOUT\n");
      splog(RED, "Error: get_work() failed with ecode(%d)\n", ecode); 
      return VERROR;
   }
   return VEOK;
} /* end get_work() */

/**
 * Send work to a node/pool.
 * Protocol...
 *    Perform Mochimo Network three-way handshake.
 *    Construct solution data in NODE.tx to send.
 *    Send OP code "Block Found" (OP_FOUND).
 * Data Sent...
 *    tx,              TX struct containing the sent data.\
 *    tx->len,         16 bit unsigned integer (little endian) containing the
 *                     length (in bytes) of data stored in tx->src_addr. (164)
 *    tx->src_addr,    byte array which contains at least 33 bytes of data...
 *       byte 0-159,   ... 160 byte block trailer containing valid nonce.
 *       byte 160-163, ... 32 bit (little endian) share difficulty.
 * Optional data sent...
 *    tx->weight,      24 bytes of space for the workers name, followed by
 *                     8 bytes of space for the workers hasrate.
 *    tx->chg_addr,    2208 byte mining address. Note, tx->len must be
 *                     increased to 6624 to represent new TX buffer size.
 * Worker Function... */
int send_work(BTRAILER *bt, byte diff)
{
   NODE node;

   int ecode, i;

   for(i = 5; i > 0; i--) {
      /* alert of re-attempt and try again in 5 seconds */
      if(i == 1)
         splog(YELLOW, "Warning: send_work() failed. Retrying...\n");
      if(i < 5)
         msleep(5000);

      /* reset ecode */
      ecode = 0;

      /* connect */
      if(callserver(&node, Peerip) != VEOK)
         continue;

      /* setup work to send */
      put16(node.tx.len, BTSIZE + 4);
      memcpy(node.tx.src_addr, bt, BTSIZE);          /* share block trailer */
      put32(node.tx.src_addr + BTSIZE, diff);        /* share dificulty     */

      /* send */
      if(send_op(&node, OP_FOUND) != VEOK) ecode = 1;

      closesocket(node.sd);
      if(ecode == 0)
         return VEOK;
   }
   splog(RED, "Error: send_work() failed with ecode(%d).\n", ecode);
   splog(RED, "       Could not send share.\n");
   
   return VERROR;
} /* send_work() */


/**
 * The Mochimo Worker */
int worker()
{
   PeachHPS hps[MAX_GPUS];

   NODE node;
   BTRAILER *host_bt;
   word32 *host_diff;
   word32 *host_rand;
   SHA256_CTX *host_bctx;

   float ahps;
   time_t Wtime, Stime, Dtime;
   uint64_t msping, msinit, haikus, thps;
   word32 solves, shares, lastshares, invalid, failed;
   byte Mining, nvml_ok, result, rdiff, sdiff, adiff;
   int i, j, k;

   /* Initialize... */
   char *metric[] = {
       "H/s", "KH/s", "MH/s", "GH/s", "TH/s"
   };                          /* ... haikurate metrics              */
   char haiku[256] = {0};      /* ... stores nonce as haiku          */
   byte Zeros[32] = {0};       /* ... Zeros (comparison hash)        */
   Mining = 0;                 /* ... Triggers mining process        */
   result = 0;                 /* ... holds result of certain ops    */
   rdiff = 0;                  /* ... tracks requested difficulty    */
   sdiff = 0;                  /* ... tracks solving difficulty      */
   adiff = 0;                  /* ... tracks auto difficulty buff    */
   solves = 0;                 /* ... block solve count              */
   shares = 0;                 /* ... valid share count              */
   invalid = 0;                /* ... invalid share count            */
   failed = 0;                 /* ... failed share count             */
   lastshares = 0;             /* ... solution count (from get_work) */
   haikus = 0;                 /* ... counts total hashes performed  */

   /* Event timers */
   Wtime = Ltime - 1;    /* get work timer       */
   Stime = Ltime;        /* start time           */
   Dtime = Ltime + 30;   /* device report time   */

   /* HPS context */
   memset(hps, 0, 64 * sizeof(PeachHPS));

   /* Local worker data */
   memset(&Wbctx, 0, sizeof(Wbctx));
   memset(&Wbt, 0, sizeof(Wbt));
   put64(Wbt.bnum, One);

   /* Host data pointers */
   host_bt = (BTRAILER *) node.tx.src_addr;
   host_diff = (word32 *) (node.tx.src_addr + BTSIZE);
   host_rand = (word32 *) (node.tx.src_addr + BTSIZE + 4);
   host_bctx = (SHA256_CTX *) (node.tx.src_addr + BTSIZE + 4 + 16);

#ifdef CUDANODE
   /* ... enhanced NVIDIA stats reporting */
   nvml_ok = init_nvml();
#endif

   /* Main miner loop */
   cplog(YELLOW, "\nStarting Mochimo Worker %s...\n", VERSIONSTR);
   while(Running) {
      Ltime = time(NULL);

      while(Ltime >= Wtime) {
         Wtime = time(NULL) + Interval;

         /* get work from host */
         msping = timestamp_ms();
         if(get_work(&node) != VEOK) {
            put64(host_bt->bnum, Zeros);
            Mining = 0;
         }
         msping = timestamp_ms() - msping;

         /* speed up polling if network is paused *
         Wtime = time(NULL) + (cmp64(bt.bnum,Zeros) != 0 ? Interval :
                               Interval/10 == 0 ? 1 : Interval/10);*/

         /* check for autodiff adjustment conditions */
         if(Difficulty == 255 && lastshares + 2 < shares) {
            for(i = shares - lastshares + 2; i > 0; i /= 3)
               adiff++;
            splog(YELLOW, "AutoDiff | Adjust Difficulty %d -> %d\n",
                  sdiff, rdiff + adiff);
         }
         /* reset autodiff share indicator */
         lastshares = shares;

         /* check for work updates
          * ...change to requested difficulty
          * ...change to auto difficulty
          * ...change to block trailer */
         if(rdiff != *host_diff ||
            (Difficulty == 255 && sdiff != rdiff + adiff) ||
            memcmp((byte *) &Wbt, (byte *) host_bt, 92) != 0) {

            /* update requested diff and random */
            rdiff = *host_diff;
            if(!iszero(host_rand, 16))
               srand2(get32(host_rand),
                      get32(host_rand + 4),
                      get32(host_rand + 4 + 4));

            /* switch difficulty handling to auto if manual too low */
            if(Difficulty != 0 && Difficulty != 255 && Difficulty < rdiff) {
               splog(RED, "Difficulty is lower than required! (%d < %d)\n",
                     Difficulty, rdiff);
               splog(YELLOW, "Switching difficulty to host...\n");
               Difficulty = 0;
            }
            if(Difficulty == 0)
               sdiff = rdiff;
            else if(Difficulty == 255)
               sdiff = rdiff + adiff;
            else
               sdiff = Difficulty;

            /* Report on work status */
            if(cmp64(host_bt->bnum, Zeros) == 0) {
               if(Mining) {
                  Mining = 0;
                  splog(YELLOW, "No  Work | Waiting for network activity "
                                "[%" PRIu64 "ms]\n", msping);
               }
            } else {
               Mining = 1;
               splog(YELLOW, "New Work | 0x%s... b%s, d%d, t%d "
                             "[%" PRIu64 "ms]\n", addr2str(host_bt->mroot),
                             bnum2hex_short(host_bt->bnum), rdiff,
                             get32(host_bt->tcount), msping);
            }

            /* on phash change, initialize new Peach map */
            if(!iszero(host_bt->phash, HASHLEN)) {
               if(memcmp(Wbt.phash, host_bt->phash, HASHLEN) != 0) {
                  if(!iszero(Wbt.phash, HASHLEN))
                     uninit_miner();
                  splog(YELLOW, "NewBlock | Initializing Peach Map... ");
                  msinit = timestamp_ms();
                  result = init_miner(host_bt, sdiff);
                  msinit = timestamp_ms() - msinit;
                  cplog(YELLOW, "[%" PRIu64 "ms]\n", msinit);
               } else result = update_miner(host_bt, sdiff);
               /* check initialization */
               if(result != VEOK) {
                  splog(RED, "InitFail | Check Devices...\n");
                  Mining = 0;
               } else {
                  /* update local bt and bctx */
                  memcpy((byte *) &Wbt, (byte *) host_bt, BTSIZE);
                  memcpy((byte *) &Wbctx, (byte *) host_bctx, sizeof(Wbctx));
               }
            }
         }
         /* extra output */
         if(Trace) {
            printf("  Sharediff=%u | Lseed2=0x%08X | Lseed3=0x%08X | Lseed4=0x%08X\n",
                   sdiff, Lseed2, Lseed3, Lseed4);
            printf("  bt= ");
            for(i = 0; i < 92; i++) {
               if(i % 16 == 0 && i)
                  printf("\n      ");
               printf("%02X ", ((byte *) &Wbt)[i]);
            }
            printf("...00\n");
            printf("bctx= ");
            for(i = 0; i < sizeof(Wbctx); i++) {
               if(i % 16 == 0 && i)
                  printf("\n      ");
               printf("%02X ", ((byte *) &Wbctx)[i]);
            }
            printf("\n");
         }
      }

      if(Ltime >= Dtime) {
         Dtime = time(NULL) + 30;
         thps = 0;
         if(Mining) {
            /* print individual device haikurates */
            for(i = 0; i < 64; i++) {
               if(hps[i].t_start > 0) {
                  if(i == 0)
                     splog(0, "Solving ");
                  ahps = hps[i].ahps;
                  thps += hps[i].ahps;
                  for(j = 0; ahps > 1000 && j < 4; j++)
                     ahps /= 1000;
                  cplog(0, " | %d: %.02f %s", i, ahps, metric[j]);
               }
            }
            /* print a "total haikurate" if more than one device */
            if(hps[1].t_start > 0) {
               ahps = thps;
               for(j = 0; ahps > 1000 && j < 4; j++)
                  ahps /= 1000;
               cplog(0, " | Total: %.02f %s", ahps, metric[j]);
            }
            cplog(0, "\n");
         }
         /* update total hashrate for TX struct */
         put64(Weight + 24, &thps);
      }

      /* do the thing */
      if(Mining) {

#ifdef CUDANODE
         /* Run the peach cuda miner */
         Blockfound = cuda_peach_worker(hps, (byte *) &Wbt, &Running);
#endif

         if(!Running) continue;
         if(Blockfound) {
            /* ... better double check share before sending */
            if(peach(&Wbt, sdiff, NULL, 1)) {
               invalid++;
               splog(RED, "Error: The Mochimo gods have rejected your share :(\n");
            } else {
               if(sdiff >= get32(Wbt.difficulty) ||
                  !peach(&Wbt, get32(Wbt.difficulty), NULL, 1)){
                  /* record a block solve */
                  solves++;
                  /* put solve time in trailer */
                  put32(Wbt.stime, time(NULL));
                  /* finish block hash */
                  sha256_update(&Wbctx, Wbt.nonce, HASHLEN + 4);
                  sha256_final(&Wbctx, Wbt.bhash);
                  /* Mmmm... Nice haiku */
                  trigg_expand2(Wbt.nonce, haiku);
                  printf("\n%s\n\n", haiku);
               }
               /* Offer share to the Host */
               msping = timestamp_ms();
               if(send_work(&Wbt, sdiff) == VEOK) {
                  msping = timestamp_ms() - msping;
                  shares++;
                  /* Estimate Share Rate */
                     /* add to total haikus */
                     haikus += (1 << sdiff);
                     /* calculate average haikurate over session */
                     ahps = haikus / (time(NULL) - Stime);
                     /* get haikurate metric */
                     for(i = 0; i < 4; i++) {
                        if(ahps < 1000) break;
                        ahps /= 1000;
                     }
                  /* end Estimate Share Rate */
                  /* Output share statistics */
                  splog(GREEN, "Success! | Solves: %u / Shares: %u / "
                        "Invalid: %u / Failed: %u [%lums]\n", solves,
                        shares, invalid, failed, msping);
                  splog(0, "Estimated Share Rate: %.02f %s\n",
                        ahps, metric[i]);
               } else
                  failed++;
            }
            /* reset solution */
            Blockfound = 0;
         }
      } else /* Chillax if not Mining */
         msleep(1000);

   } /* end while(Running) */

   return VEOK;
} /* end worker() */


void usage(void)
{
   printf("usage: worker [-option...]\n"
          "         -aS        set proxy ip to S\n"
          "         -pN        set proxy port to N\n"
          "         -iN        set polling interval to N\n"
          "         -dN        set difficulty to N\n"
          "         -wNAME     set worker name to NAME\n"
          "         -tN        set Trace to N (0, 1)\n"
          "         -u         trigger username and password input\n"
          "         -uUSER     set username to USER, no password\n"
          "         -l         open mochi.log file\n"
          "         -lFNAME    open log file FNAME\n"
   );
   exit(0);
} /* end worker() */


/**
 * Initialise data and call the worker */
int main(int argc, char **argv)
{
   static int j;
   static byte endian[] = { 0x34, 0x12 };
   static char *cp;

   byte Userpass;             /* triggers input of User & Pwd     */
   SHA256_CTX ictx;           /* for hashing User | User & Pwd    */

   /* sanity checks */
   if(sizeof(word32) != 4) fatal("word32 should be 4 bytes");
   if(sizeof(TX) != TXBUFFLEN || sizeof(LTRAN) != (TXADDRLEN + 1 + TXAMOUNT)
      || sizeof(BTRAILER) != BTSIZE)
      fatal("struct size error.\nSet compiler options for byte alignment.");    
   if(get16(endian) != 0x1234)
      fatal("little-endian machine required for this build.");

#ifdef _WINSOCKAPI_
   /* Initiate the use of the Winsock DLL */
   static WORD wsaVerReq;
   static WSADATA wsaData;

   wsaVerReq = 0x0101;	/* version 1.1 */
   if(WSAStartup(wsaVerReq, &wsaData) == SOCKET_ERROR)
      fatal("WSAStartup()");
   Needcleanup = 1;
#endif

   if(read_data(Maddr, TXADDRLEN, "maddr.dat") != TXADDRLEN)
      memset(Maddr, 0, TXADDRLEN);

   /**
    * Seed ID token generator */
   srand16(time(&Ltime) ^ get32(Maddr) ^ getpid());
   srand2(Ltime ^ get32(Maddr+4), 0, 123456789 ^ get32(Maddr+8) ^ getpid());

   /**
    * Set Defaults */
   Peerip = 0x0100007f;    /* Default host IP */
   Port = Dstport = PORT1; /* Default host port (2095) */
   Interval = 10;          /* Default get_work() interval seconds */
   Difficulty = 0;         /* Default difficulty (0 = host) */
   Dynasleep = 10000;      /* Default 10 ms */
   Blockfound = 0;         /* Default share not (yet) found */
   Running = 1;


   /*******************/
   /* TEMPORARY ALERT */
#ifdef CPUNODE
   splog(RED, "\nError: The Mochimo CPU worker is not currently supported :(\n");
   splog(RED, "       Please compile CUDA for now\n\n");
   return 1;
#endif
   /* end TEMPORARY ALERT */
   /***********************/


   /**
    * Parse command line arguments */
   for(j = 1; j < argc; j++) {
      if(argv[j][0] != '-') usage();
      switch(argv[j][1]) {
         case 'a':  if(argv[j][2]) {
                       cp = &argv[j][2];
                       Peerip = str2ip(cp);
                       if(!Peerip) {
                         cplog(RED, "Error: Peerip is invalid, addr=%s\n", cp);
                         return VERROR;
                       }
                    }
                    break;
         case 'p':  Port = Dstport = atoi(&argv[j][2]);
                    break;
         case 'i':  if(argv[j][2]) {
                       Interval = atoi(&argv[j][2]);
                       if(!Interval) {
                          cplog(RED, "Error: Interval must not a number "
                                "greater than Zero, Interval=%d", Interval);
                          return VERROR;
                       }
                    }
                    break;
         case 'w':  if(argv[j][2]) {
                       cp = &argv[j][2];
                       /* Reduce Worker Name length to fit into 24 bytes */
                       if(strlen(cp) > 23) {
                          cp[23] = 0;
                          cplog(YELLOW, "Warning: Worker name truncated to 23 "
                                "characters. Worker: %s\n", cp);
                       }
                       /* update worker name in Weight byte array */
                       strcpy(Weight, cp);
                    }
                    break;
         case 'd':  if(argv[j][2]) Difficulty = atoi(&argv[j][2]);
                    break;
         case 't':  Trace = atoi(&argv[j][2]); /* set trace level  */
                    break;
         case 'u':  if(argv[j][2]) {
                       cp = &argv[j][2];
                       sha256_init(&ictx);
                       sha256_update(&ictx, (byte *) cp, strlen(cp));
                       sha256_final(&ictx, Userhash);
                    } else {
                       cplog(YELLOW, "Userhash activated...\n");
                       sha256_init(&ictx);
                       /* obtain username */
                       cp = ask_input("Username: ", 0);
                       /* hash and clear username */
                       sha256_update(&ictx, (byte *) cp, strlen(cp));
                       memset(cp, 0, strlen(cp));
                       if(cp[0]) {
                          cplog(RED, "Fatal Error: Username was not cleared from memory\n");
                          return VERROR;
                       }
                       /* obtain password */
                       cp = ask_input("Password: ", 1);
                       /* hash and clear username */
                       sha256_update(&ictx, (byte *) cp, strlen(cp));
                       memset(cp, 0, strlen(cp));
                       if(cp[0]) {
                          cplog(RED, "Fatal Error: Password was not cleared from memory\n");
                          return VERROR;
                       }
                       /* finalise hash */
                       sha256_final(&ictx, Userhash);
                    }
                    break;
         case 'l':  if(argv[j][2]) /* open log file used by plog()   */
                       Logfp = fopen(&argv[j][2], "a");
                    else
                       Logfp = fopen(LOGFNAME, "a");
                    break;
         default:   usage();
      }  /* end switch */
   }  /* end for j */

   /* Redirect signals */
   for(j = 0; j <= NSIG; j++)
      signal(j, SIG_IGN);
   signal(SIGINT, sigterm);  /* signal interrupt, ctrl+c */
   signal(SIGTERM, sigterm); /* signal terminate, kill */
   /* Not working on windows, find a fix during multithread overhaul
   signal(SIGCHLD, SIG_DFL); /* default signal handling, so waitpid() works */


   /**
    * Introducing! */
   printf(
   "   __  __         _    _            __      __       _\n"
   "  |  \\/  |___  __| |_ (_)_ __  ___  \\ \\    / /__ _ _| |_____ _ _\n"
   "  | |\\/| / _ \\/ _| ' \\| | '  \\/ _ \\  \\ \\/\\/ / _ \\ '_| / / -_) '_|\n"
   "  |_|  |_\\___/\\__|_||_|_|_|_|_\\___/   \\_/\\_/\\___/_| |_\\_\\___|_|\n"
   "                        Copyright (c) 2019 Adequate Systems, LLC.\n"
   "           @@@@@@                            All rights reserved.\n"
   "        @@@  @@  @@@\n"
   "     @@@    @@      @@@    Worker~ %.23s\n"
   "    @@  @@@@@@@@@@@@  @@     BinBuiltOn... " __DATE__ " " __TIME__ "\n"
   "   @@  @@  @@  @@  @@  @@    BinVersion... " VERSIONSTR "\n"
   "   @@  @@  @@  @@  @@  @@    Connection... %s:%hu\n"
   "   @@  @@  @@  @@  @@  @@    Check work... %u seconds\n"
   "   @@  @@  @@  @@  @@  @@    Difficulty... %u (%s)\n"
   "    @@@@@@@@@@@@@@@@@@@@     Userhashed... %s\n"
   "      @@@          @@@\n"
   "         @@@@@@@@@@        Initializing...\n\n",
   Weight[0] ? (char *) Weight : "", ntoa((byte*) &Peerip), Port, Interval,
   Difficulty, Difficulty == 255 ? "auto" : Difficulty > 0 ? "manual" : "host",
   !iszero(Userhash, HASHLEN) ? "yes" : "no");

   if(!iszero(Maddr, TXADDRLEN)) {
      printf("Mining address: 0x");
      for(j = 0; j < 24; j++)
         printf("%02x", Maddr[j]);
      printf("...\n");
   } else printf("Mining address: <use host>\n");
   printf("\n");

   /**
    * Enjoy the header for a moment */
   msleep(2000);

   /**
    * Start the worker*/
   worker();

#ifdef _WINSOCKAPI_
   /* Cleanup Winsock DLL when done */
   if(Needcleanup)
      WSACleanup();
#endif

   /**
    * End */
   cplog(0, "\n");
   splog(0, "Worker exiting...\n");
   return 0;
} /* end main() */
