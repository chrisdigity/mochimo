/* worker.c
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * The Mochimo Project Worker Software
 * This file builds a worker.
 *
 * Revised: 28 April 2019
*/

#define VERSIONSTR "Version 0.8~beta"

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

/* Prototypes */
#include "proto.h"

/* Overrides */
int pinklist(word32 ip) { return VEOK; }
int epinklist(word32 ip) { return VEOK; }
void stop_mirror(void) { /* do nothing */ }

/* Include global data */
#include "data.c"          /* System wide globals              */
byte Interval;             /* get_work() poll interval seconds */
byte Mining;               /* triggers the mining process      */
byte Showhaiku;            /* triggers the output of haiku     */
char *Name;                /* pointer to worker name           */

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

/* Send transaction in np->tx */
int sendtx(NODE *np)
{
   int count;
   TX *tx;

   tx = &np->tx;

   put16(tx->version, PVERSION);
   put16(tx->network, TXNETWORK);
   put16(tx->trailer, TXEOT);
   put16(tx->id1, np->id1);
   put16(tx->id2, np->id2);
   memcpy(np->tx.weight, Weight, HASHLEN);
   crctx(tx);
   count = send(np->sd, TXBUFF(tx), TXBUFFLEN, 0);
   if(count != TXBUFFLEN)
      return VERROR;
   return VEOK;
}  /* end sendtx2() */


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
}

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
}

/**
 * Un-Initialize miner and free memory allocations where appropriate */
int uninit_miner()
{
#ifdef CUDANODE
   /* Free allocated memory on CUDA devices */
   free_cuda_peach();
#endif

   return VEOK;
}

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

   /* clear any existing TX data */
   memset(TXBUFF(&(np->tx)), 0, TXBUFFLEN);

   /* connect and retrieve work */
   if(callserver(np, Peerip) != VEOK) {
      splog(RED, "Error: Could not connect to %s...\n", ntoa((byte *) &Peerip));
      return VERROR;
   }
   if(send_op(np, OP_SEND_BL) != VEOK) ecode = 1;
   if(!ecode && rx2(np, 1, 10) != VEOK) ecode = 2;
   if(!ecode && get16(np->tx.opcode) != OP_SEND_BL) ecode = 3;

   closesocket(np->sd);
   if(ecode) {
      splog(RED, "Error: get_work() failed with ecode(%d)\n", ecode); 
      return VERROR;
   }
   return VEOK;
}

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
 *    tx->dst_addr,    2208 byte mining address. Note, tx->len must be
 *                     increased to 4408 to represent new TX buffer size.
 * Worker Function... */
int send_work(NODE *np, BTRAILER *bt, byte diff, uint64_t thps)
{
   int ecode = 0;
   
   /* clear any existing TX data */
   memset(TXBUFF(&(np->tx)), 0, TXBUFFLEN);
   
   /* connect */
   if(callserver(np, Peerip) != VEOK) {
      splog(RED, "Error: Could not connect to %s...\n", ntoa((byte *) &Peerip));
      return VERROR;
   }

   /* setup worker details and work to send */
   if(Name)
      strcpy(np->tx.weight, Name);               /* worker name         */
   put64(&(np->tx.weight[24]), &thps);           /* worker hashrate     */
   memcpy(np->tx.src_addr, bt, 160);             /* share block trailer */
   memcpy(np->tx.src_addr+160, &diff, 4);        /* share dificulty     */
   if(iszero(Maddr, TXADDRLEN))
      put16(np->tx.len, 164);
   else {
      memcpy(np->tx.dst_addr, Maddr, TXADDRLEN); /* mining address      */
      put16(np->tx.len, 4408);
   }

   /* send */
   if(send_op(np, OP_FOUND) != VEOK) ecode = 1;
   
   /* return status *//*
   if(!ecode && rx2(np, 1, 10) != VEOK) ecode = 2;
   if(!ecode && get16(np->tx.opcode) != OP_FOUND) ecode = 3;
   */
   
   closesocket(np->sd);
   if(ecode) {
      splog(RED, "Error: send_work() failed with ecode(%d)\n", ecode); 
      return VERROR;
   }
   return VEOK;
}


/**
 * The Mochimo Worker */
int worker(char *addr)
{
   PeachHPS hps[MAX_GPUS];
   BTRAILER bt;
   NODE node;
   TX *tx;
   float ahps, thps;
   time_t Wtime, Stime;
   uint64_t msping, msinit;
   word32 shares, lastshares, haikus;
   byte rdiff, sdiff, adiff;
   byte nvml_ok, result;
   int i, j, k;
   
   /* Initialize... */
   char *metric[] = {
       "H/s", "KH/s", "MH/s", "GH/s", "TH/s"
   };                          /* ... haikurate metrics              */
   char haiku[256];            /* ... stores nonce as haiku          */
   byte Zeros[32] = {0};       /* ... Zeros (comparison hash)        */
   byte lasthash[32] = {0};    /* ... lasthash (comparison hash)     */
   result = 0;                 /* ... holds result of certain ops    */
   rdiff = 0;                  /* ... tracks required difficulty     */
   sdiff = 0;                  /* ... tracks solving difficulty      */
   adiff = 0;                  /* ... tracks auto difficulty buff    */
   shares = 0;                 /* ... solution count                 */
   lastshares = 0;             /* ... solution count (from get_work) */
   haikus = 0;                 /* ... counts total hashes performed  */
   tx = &(node.tx);            /* ... store pointer to node.tx       */

   /* ... event timers */
   Ltime = time(NULL);   /* UTC seconds          */
   Wtime = Ltime - 1;    /* get work timer       */
   Stime = Ltime;        /* start time           */

   /* ... block trailer height */
   put64(bt.bnum, One);
   
   /* Check worker settings */
   if((Peerip = str2ip(addr)) == 0) {
      splog(RED, "Error: Peerip is invalid, addr=%s\n", addr);
      return VERROR;
   }
   if(Interval == 0) {
      splog(RED, "Error: Interval must be greater than Zero (0)\n");
      return VERROR;
   }
   if(Name && strlen(Name) > 23) {
      Name[23] = 0;
      splog(YELLOW, "Warning: A worker name can only be 23 characters long. Your\n"
             "worker name has been shortened to: %s\n\n", Name);
   }
   
   /* ... wipe HPS context */
   memset(hps, 0, 64 * sizeof(PeachHPS));
   
#ifdef CUDANODE
   /* ... enhanced NVIDIA stats reporting */
   nvml_ok = init_nvml();
#endif

   /* Main miner loop */
   while(Running) {
      Ltime = time(NULL);

      if(Ltime >= Wtime) {
         /* get work from host */
         msping = timestamp_ms();
         if(get_work(&node) == VEOK) {
            msping = timestamp_ms() - msping;
            
            /* check for autodiff adjustment conditions */
            if(Difficulty == 255 && lastshares + 2 < shares) {
               for(i = shares - lastshares + 2; i > 0; i /= 3)
                  adiff++;
               splog(YELLOW, "AutoDiff | Adjust Difficulty %d -> %d\n",
                     sdiff, rdiff + adiff);
            }

            /* check data for new work
             * ...change to requested difficulty
             * ...change to auto difficulty
             * ...change to block trailer */
            if(rdiff != TRANBUFF(tx)[160] ||
               (Difficulty == 255 && sdiff != rdiff + adiff) ||
               memcmp((byte *) &bt, TRANBUFF(tx), 92) != 0) {
               
               /* new work received
                * ...update host difficulty
                * ...update block trailer
                * ...update rand2() sequence (if supplied) */
               rdiff = TRANBUFF(tx)[160];
               memcpy((byte *) &bt, TRANBUFF(tx), 160);
               if(get16(tx->len) > 164)
                  srand2(get32(TRANBUFF(tx)+164),
                         get32(TRANBUFF(tx)+164+4),
                         get32(TRANBUFF(tx)+164+4+4));
               
               /* switch difficulty handling to auto if manual too low */
               if(Difficulty != 0 && Difficulty != 255 && Difficulty < rdiff) {
                  splog(RED, "Difficulty is lower than required! (%d < %d)\n",
                        Difficulty, rdiff);
                  splog(YELLOW, "Switching difficulty to auto...\n");
                  Difficulty = 0;
               }
               if(Difficulty == 0)
                  sdiff = rdiff;
               else if(Difficulty == 255)
                  sdiff = rdiff + adiff;
               else
                  sdiff = Difficulty;
               
               /* Report on work status */
               if(cmp64(bt.bnum, Zeros) == 0) {
                  splog(YELLOW, "No Work  | Waiting on host...\n");
                  Mining = 0;
               } else {
                  splog(YELLOW, "New Work | %s, d%d, t%d | ",
                        bnum2hex_short(bt.bnum), rdiff, get32(bt.tcount));
                  
                  /* free any miner variables ONLY ON NEW PHASH */
                  if(memcmp(lasthash, Zeros, 32) != 0 &&
                     memcmp(lasthash, bt.phash, 32) != 0) {
                     uninit_miner();
                     memset(lasthash, 0, 32);
                  }
                  
                  /* initialize any miner variables ONLY ON NEW PHASH */
                  if(memcmp(lasthash, bt.phash, 32) != 0) {
                     printf("Initializing... ");
                     fflush(stdout);
                     msinit = timestamp_ms();
                     result = init_miner(&bt, sdiff);
                  } else {
                     printf("Updating...");
                     fflush(stdout);
                     msinit = timestamp_ms();
                     result = update_miner(&bt, sdiff);
                  }
                  printf("[%" PRIu64 "ms]\n", timestamp_ms() - msinit);
                  
                  /* check initialization */
                  if(result == VEOK) {
                     splog(0, "Solving  | %s, d%d, t%d\n",
                           bnum2hex_short(bt.bnum), sdiff, get32(bt.tcount));
                     Mining = 1;
                     memcpy(lasthash, bt.phash, 32);
                  } else {
                     splog(RED, "InitFail | Check GPUs...\n");
                     Mining = 0;
                     memset(lasthash, 0, 32);
                  }
               }
            }
         }
         
         if(cmp64(bt.bnum, One) > 0) {
            /* print individual device haikurates */
            splog(0, "Devices ");
            thps = 0;
            for(i = 0; i < 64; i++) {
               if(hps[i].t_start > 0) {
                  ahps = hps[i].ahps;
                  thps += ahps;
                  for(j = 0; ahps > 1000 && j < 4; j++)
                     ahps /= 1000;
                  printf(" | %d: %.02f %s", i, ahps, metric[j]);
               }
            }
            /* print a "total haikurate" if more than one device */
            if(hps[1].t_start > 0) {
               for(j = 0; thps > 1000 && j < 4; j++)
                  thps /= 1000;
               printf(" | Total: %.02f %s", thps, metric[j]);
            }
            printf("\n");
            /* extra output */
            if(Trace) {
               printf("  Sharediff=%u | Lseed2=0x%08X | Lseed3=0x%08X | Lseed4=0x%08X\n",
                      sdiff, Lseed2, Lseed3, Lseed4);
               printf("  bt= ");
               for(i = 0; i < 92; i++) {
                  if(i % 16 == 0 && i)
                     printf("\n      ");
                  printf("%02X ", ((byte *) &bt)[i]);
               }
               printf("...00\n");
            }
         }
         
         /* speed up polling if network is paused */
         Wtime = time(NULL) + (cmp64(bt.bnum,Zeros) != 0 ? Interval :
                               Interval/10 == 0 ? 1 : Interval/10);
         
         /* reset autodiff share indicator */
         lastshares = shares;
      }

      /* do the thing */
      if(Mining) {

#ifdef CUDANODE
         /* Run the peach cuda miner */
         Blockfound = cuda_peach_worker(hps, (byte *) &bt, &Running);
#endif
         
         if(!Running) continue;
         if(Blockfound) {
            /* ... better double check share before sending */
            if(peach(&bt, sdiff, NULL, 1)) {
               splog(RED, "Error: The Mochimo gods have rejected your share :(\n");
               if(Trace) {
                  printf("Checking Difficulty...\n");
                  for(i = 0; i < sdiff; i++) {
                     if(peach(&bt, i, NULL, 1)) {
                        printf("Difficulty %d FAILED...\n", i);
                        break;
                     } else {
                        printf("Difficulty %d PASS...\n", i);
                     }
                  }
               }
            } else {
               if(Showhaiku) {
                  /* Mmmm... Nice haiku */
                  trigg_expand2(bt.nonce, haiku);
                  printf("\n%s\n\n", haiku);
               }
               /* Offer share to the Host */
               for(i = 4, j = 0; i > -1; i--) {
                  msping = timestamp_ms();
                  if(send_work(&node, &bt, sdiff, (uint64_t) thps) == VEOK) {
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
                     splog(GREEN, "Success! | Shares: %u | Est. sRate "
                             "%.02f %s [%lums]\n", shares, ahps,
                             metric[i], msping);
                     break;
                  }
                  msleep(5000);
               }
               if(i < 0)
                  splog(RED, "Failed to send share to host :(\n");
            }
            /* extra output */
            if(Trace) {
               printf("  Sharediff=%u | "
                      "Lseed2=0x%08X | Lseed3=0x%08X | Lseed4=0x%08X\n",
                      sdiff, Lseed2, Lseed3, Lseed4);
               printf("  bt= ");
               for(i = 0; i < 124; i++) {
                  if(i % 16 == 0 && i)
                     printf("\n      ");
                  printf("%02X ", ((byte *) &bt)[i]);
               }
               printf("...00\n");
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
          "         -l         open mochi.log file\n"
          "         -lFNAME    open log file FNAME\n"
          "         -e         enable error.log file\n"
          "         --haiku    enable haiku output\n"
   );
   exit(0);
}


/**
 * Initialise data and call the worker */
int main(int argc, char **argv)
{
   static int j;
   static byte endian[] = { 0x34, 0x12 };
   static char *Hostaddr = "127.0.0.1";
   static char maddrstr[33] = {0};
   char buff[3] = "0x";
   
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
   
   
   /**
    * Seed ID token generator */
   read_data(Maddr, TXADDRLEN, "maddr.dat");
   srand16(time(&Ltime) ^ get32(Maddr) ^ getpid());
   srand2(Ltime ^ get32(Maddr+4), 0, 123456789 ^ get32(Maddr+8) ^ getpid());
   
   /**
    * Set Defaults */
   Port = Dstport = PORT1; /* Default port 2095 */
   Interval = 20;          /* Default get_work() interval seconds */
   Mining = 0;             /* Default not (yet) mining */
   Showhaiku = 0;          /* Default avoid showing haiku :( */
   Difficulty = 0;         /* Default difficulty (0 = host) */
   Dynasleep = 10000;      /* Default 10 ms */
   Blockfound = 0;         /* Default share not (yet) found */
   Running = 1;
   
   
   /*******************/
   /* TEMPORARY ALERT */
#ifdef CPUNODE
   splog(RED, "Error: The Mochimo CPU worker is not currently supported :(\n");
   splog(RED, "       Please compile CUDA for now\n");
   return 1;
#endif
   /* end TEMPORARY ALERT */
   /***********************/
   
   
   /**
    * Parse command line arguments */
   for(j = 1; j < argc; j++) {
      if(argv[j][0] != '-') usage();
      switch(argv[j][1]) {
         case 'a':  if(argv[j][2]) Hostaddr = &argv[j][2];
                    break;
         case 'p':  Port = Dstport = atoi(&argv[j][2]);
                    break;
         case 'i':  if(argv[j][2]) Interval = atoi(&argv[j][2]);
                    break;
         case 'w':  if(argv[j][2])
                       Name = &argv[j][2];
         case 'd':  if(argv[j][2]) Difficulty = atoi(&argv[j][2]);
                    break;
         case 't':  Trace = atoi(&argv[j][2]); /* set trace level  */
                    break;
         case 'l':  if(argv[j][2]) /* open log file used by plog()   */
                       Logfp = fopen(&argv[j][2], "a");
                    else
                       Logfp = fopen(LOGFNAME, "a");
                    break;
         case 'e':  Errorlog = 1;  /* enable "error.log" file */
                    break;
         case '-':  if(strcmp(&argv[j][1], "-haiku") == 0)
                       Showhaiku = 1;
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
   
   /* Stringify Mining Address */
   if(iszero(Maddr, TXADDRLEN) == 0) {
      strcat(maddrstr, buff);
      for(j = 0; j < 16; j++) {
         sprintf(buff, "%02x", Maddr[j]);
         strcat(maddrstr, buff);
      }
   } else strcat(maddrstr, "none - using host address");
   
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
   "     @@@    @@      @@@    Worker~ %.23s%s\n"
   "    @@  @@@@@@@@@@@@  @@     MiningAddr... %s\n"
   "   @@  @@  @@  @@  @@  @@    BinBuiltOn... %s %s\n"
   "   @@  @@  @@  @@  @@  @@    BinVersion... " VERSIONSTR "\n"
   "   @@  @@  @@  @@  @@  @@    Connection... %s:%hu\n"
   "   @@  @@  @@  @@  @@  @@    Check work... %u seconds\n"
   "    @@@@@@@@@@@@@@@@@@@@     Difficulty... %u (%s)\n"
   "      @@@          @@@\n"
   "         @@@@@@@@@@        Starting up...\n\n",
   Name ? Name : "", Name ? strlen(Name) > 23 ? "..." : "" : "",
   maddrstr, __DATE__, __TIME__, Hostaddr, Port, Interval, Difficulty,
   Difficulty == 255 ? "automatic" : Difficulty > 0 ? "manual" : "host");

   /**
    * Enjoy the header for a moment */
   msleep(2000);
   
   /**
    * Start the worker*/
   worker(Hostaddr);

#ifdef _WINSOCKAPI_
   /* Cleanup Winsock DLL when done */
   if(Needcleanup)
      WSACleanup();
#endif

   /**
    * End */
   printf("\n\nWorker exiting...\n\n");
   return 0;
} /* end main() */
