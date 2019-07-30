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

/* Terminal Beautify */
#define NRM     "\x1B[0m"
#define BOLD    "\x1B[1m"  /* decoration */
#define DIM     "\x1B[2m" 
#define ULINE   "\x1B[4m" 
#define BLINK   "\x1B[5m" 
#define RED     "\x1B[31m" /* colors */
#define GREEN   "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define BLUE    "\x1B[34m"
#define MAGENTA "\x1B[35m"
#define CYAN    "\x1B[36m"
#define WHITE   "\x1B[37m"

#define VERSIONSTR "Version 0.7" YELLOW "~beta" NRM

/* Core includes */
#include "config.h"
#include "sock.h"     /* BSD sockets */
#include "mochimo.h"

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
#include "util.c"
#include "sock.c"          /* inet utilities                   */
#include "connect.c"       /* make outgoing connection         */
#include "call.c"          /* callserver() and friends         */
#include "str2ip.c"

/* Mining algorithm */
#include "algo/peach/peach.c"
#ifdef CUDANODE
   /* CUDA Peach algo prototypes */
   #include "algo/peach/cuda_peach.h"
#endif

/**
 * Clear run flag, Running on SIGTERM */
void sigterm(int sig)
{
   signal(SIGTERM, sigterm);
   Running = 0;
}

/**
 * Send packet: set advertised fields and crc16.
 * Returns VEOK on success, else VERROR. */
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
   put64(np->tx.cblock, Cblocknum);  /* 64-bit little-endian */
   memcpy(np->tx.cblockhash, Cblockhash, HASHLEN);
   memcpy(np->tx.pblockhash, Prevhash, HASHLEN);
   if(get16(np->tx.opcode) != OP_TX)  /* do not copy over TX ip map */
      memcpy(np->tx.weight, Weight, HASHLEN);
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
 * Converts 8 bytes of little endian data into a hexadecimal
 * character array without extraneous Zeroes.
 * Always writes the first byte of data. */
char *bytes2hex_trim(byte *bnum)
{
   static char result[19];
   char next[3] = "0x";
   int pos = 7;
   
   /* clear result and begin with "0x" */
   result[0] = '\0';
   strcat(result, next);
   /* work backwards to find first value */
   while(bnum[pos] == 0 && pos > 0) pos--;
   /* convert/Store remaining data */
   while(pos >= 0) {
      sprintf(next, "%02x", bnum[pos]);
      strcat(result, next);
      pos--;
   }

   return result;
}

/**
 * printf() with a timestamp prefix */
void wprintf(char *fmt, ...)
{
   va_list argp;
   
   /* get timestamp */
   time_t t = time(NULL);
   struct tm tm = *localtime(&t);
   
   /* return if there's nothing to print */
   if(fmt == NULL) return;
   /* print timestamp prefix */
   printf("[%d-%02d-%02d %02d:%02d:%02d] ",            /* Format */
         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, /*  Date  */
         tm.tm_hour, tm.tm_min, tm.tm_sec);            /*  Time  */
   
   /* print remaining data */
   va_start(argp, fmt);
   vfprintf(stdout, fmt, argp);
   va_end(argp);
   /* flush to stdout */
   fflush(stdout);
}

/**
 * Return current milliseconds for timing functions */
uint64_t getms() {
    struct timeval tv; 
    gettimeofday(&tv, NULL);
    uint64_t milliseconds = tv.tv_sec*1000LL + tv.tv_usec/1000;
   
    return milliseconds;
}

/**
 * Initialize miner and allocate memory where appropriate */
int init_miner(void *ctx, BTRAILER *bt, byte diff)
{
   int initGPU;

#ifdef CUDANODE
   /* Initialize CUDA specific memory allocations
    * and check for obvious errors */
   initGPU = -1;
   initGPU = init_cuda_peach(ctx, diff, (byte *) bt);
   if(initGPU==-1) {
      wprintf("%sError: Cuda initialization failed. Check nvidia-smi%s\n", RED, NRM);
      free_cuda_peach();
      return VERROR;
   }
   if(initGPU<1 || initGPU>64) {
      wprintf("%sError: Unsupported number of GPUs detected -> %d%s\n", RED, initGPU, NRM);
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
      wprintf("\n%sError: Cuda update failed... %s", RED, NRM);
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
int get_work(NODE *np, char *addr)
{
   int ecode = 0;

   /* connect and retrieve work */
   if(callserver(np, Peerip) != VEOK) {
      wprintf("%sError: Could not connect to %s...%s\n", RED, addr, NRM);
      return VERROR;
   }
   if(send_op(np, OP_SEND_BL) != VEOK) ecode = 1;
   if(!ecode && rx2(np, 1, 10) != VEOK) ecode = 2;
   if(!ecode && get16(np->tx.opcode) != OP_SEND_BL) ecode = 3;

   closesocket(np->sd);
   if(ecode) {
      wprintf("%sError: get_work() failed with ecode(%d)%s\n", RED, ecode, NRM); 
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
 *    tx->weight,      31 characters of space for a worker name.
 * Worker Function... */
int send_work(BTRAILER *bt, byte diff, char *addr)
{
   NODE node;
   int ecode = 0;

   /* connect */
   if(callserver(&node, Peerip) != VEOK) {
      wprintf("%sError: Could not connect to %s...%s\n", RED, addr, NRM);
      return VERROR;
   }

   /* setup work to send */
   if(Name)
      strcpy(node.tx.weight, Name);
   node.tx.len[0] = 164;
   memcpy(node.tx.src_addr, bt, 160);
   memcpy(node.tx.src_addr+160, &diff, 4);

   /* send */
   if(send_op(&node, OP_FOUND) != VEOK) ecode = 1;
   
   closesocket(node.sd);
   if(ecode) {
      wprintf("%sError: send_work() failed with ecode(%d)%s\n", RED, ecode, NRM); 
      return VERROR;
   }
   return VEOK;
}


/**
 * The Mochimo Worker */
int worker(char *addr)
{
   BTRAILER bt;
   NODE node;
   TX *tx;
   float hps, thps;
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
   tx = &(node.tx);            /* ... store pointer to node.tx       */

   /* ... event timers */
   Ltime = time(NULL);   /* UTC seconds          */
   Wtime = Ltime - 1;    /* get work timer       */
   Stime = Ltime;        /* start time           */

   /* ... block trailer height */
   put64(bt.bnum, One);
   
   /* Check worker settings */
   if((Peerip = str2ip(addr)) == 0) {
      printf("%sError: Peerip is invalid, addr=%s%s\n", RED, addr, NRM);
      return VERROR;
   }
   if(Interval == 0) {
      printf("%sError: Interval must be greater than Zero (0)%s\n", RED, NRM);
      return VERROR;
   }
   if(Name && strlen(Name) > 31) {
      Name[31] = 0;
      printf("%sWarning: A worker name can only be 31 characters long. Your\n"
             "worker name has been shortened to: %s%s\n\n", YELLOW, Name, NRM);
   }
   
#ifdef CUDANODE
   /* ... CUDA context */
   PeachCudaCTX ctx[64];
   memset(ctx, 0, 64 * sizeof(PeachCudaCTX));
   /* ... enhanced NVIDIA stats reporting */
   nvml_ok = init_nvml();
#endif

   /* Main miner loop */
   while(Running) {
      Ltime = time(NULL);

      if(Ltime >= Wtime) {
         /* get work from host */
         msping = getms();
         if(get_work(&node, addr) == VEOK) {
            msping = getms() - msping;
            
            /* check for autodiff adjustment conditions */
            if(Difficulty == 255 && lastshares + 2 < shares) {
               for(i = shares - lastshares + 2; i > 0; i /= 3)
                  adiff++;
               wprintf("%sAutoDiff | Adjust Difficulty %d -> %d%s\n",
                       YELLOW, sdiff, rdiff + adiff, NRM);
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
                  wprintf("%sDifficulty is lower than required!"
                          " (%d < %d)%s\n", RED, Difficulty, rdiff, NRM);
                  wprintf("%sSwitching difficulty to auto...%s\n", YELLOW, NRM);
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
                  wprintf("%sNo Work  | Waiting on host...%s\n", YELLOW, NRM);
                  Mining = 0;
               } else {
                  wprintf("%sNew Work | %s, d%d, t%d | ", YELLOW,
                          bytes2hex_trim(bt.bnum), rdiff, get32(bt.tcount));
                  
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
                     msinit = getms();
                     result = init_miner(ctx, &bt, sdiff);
                  } else {
                     printf("Updating...");
                     fflush(stdout);
                     msinit = getms();
                     result = update_miner(&bt, sdiff);
                  }
                  printf("[%lums]%s\n", getms() - msinit, NRM);
                  
                  /* check initialization */
                  if(result == VEOK) {
                     wprintf("Solving  | %s, d%d, t%d\n",
                             bytes2hex_trim(bt.bnum), sdiff, get32(bt.tcount));
                     Mining = 1;
                     memcpy(lasthash, bt.phash, 32);
                  } else {
                     wprintf("%sInitFail | Check GPUs...%s\n", RED, NRM);
                     Mining = 0;
                  }
               }
            }
         }
         
         if(cmp64(bt.bnum, One) > 0) {
            /* print individual device haikurates */
            wprintf("Devices ");
            thps = 0;
            for(i = 0; i < 64; i++) {
               if(ctx[i].total_threads) {
                  hps = ctx[i].ahps;
                  thps += hps;
                  for(j = 0; hps > 1000 && j < 4; j++)
                     hps /= 1000;
                  printf(" | %d: %.02f %s", i, hps, metric[j]);
               }
            }
            /* print a "total haikurate" if more than one device */
            if(ctx[1].total_threads) {
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
         Blockfound = cuda_peach_worker((byte *) &bt, &Running);
#endif
         
         if(!Running) continue;
         if(Blockfound) {
            /* ... better double check share before sending */
            if(peach(&bt, sdiff, NULL, 1)) {
               wprintf("%sError: The Mochimo gods have rejected your share :(%s\n", RED, NRM);
            } else {
               if(Showhaiku) {
                  /* Mmmm... Nice haiku */
                  trigg_expand2(bt.nonce, haiku);
                  printf("\n%s\n\n", haiku);
               }
               /* Offer share to the Host */
               for(i = 4, j = 0; i > -1; i--) {
                  msping = getms();
                  if(send_work(&bt, sdiff, addr) == VEOK) {
                     msping = getms() - msping;
                     shares++;

                     /* Estimate Share Rate */
                        /* add to total haikus */
                        haikus += (1 << sdiff);
                        /* calculate average haikurate over session */
                        hps = haikus / (time(NULL) - Stime);
                        /* get haikurate metric */
                        for(i = 0; i < 4; i++) {
                           if(hps < 1000) break;
                           hps /= 1000;
                        }
                     /* end Estimate Share Rate */
                     
                     /* Output share statistics */
                     wprintf("%sSuccess! | Shares: %u | Est. sRate "
                             "%.02f %s [%lums]%s\n", GREEN, shares, hps,
                             metric[i], msping, NRM);
                     break;
                  }
                  sleep(5);
               }
               if(i < 0)
                  wprintf("%sFailed to send share to host :(%s\n", RED, NRM);
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
         usleep(1000000);

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

   /* sanity checks */
   if(sizeof(word32) != 4) fatal("word32 should be 4 bytes");
   if(sizeof(TX) != TXBUFFLEN || sizeof(LTRAN) != (TXADDRLEN + 1 + TXAMOUNT)
      || sizeof(BTRAILER) != BTSIZE)
      fatal("struct size error.\nSet compiler options for byte alignment.");    
   if(get16(endian) != 0x1234)
      fatal("little-endian machine required for this build.");
   
   /**
    * Seed ID token generator */
   srand16(time(&Ltime));
   srand2(Ltime, 0, rand16());
   
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
   wprintf("%sError: The Mochimo CPU worker is not currently supported :(%s\n", RED, NRM);
   wprintf("%s       Please compile CUDA for now%s\n", RED, NRM);
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
   signal(SIGCHLD, SIG_DFL); /* default signal handling, so waitpid() works */
   
   /**
    * Introducing! */
   printf(BOLD
   "   __  __         _    " BLUE "_" NRM BOLD "            __      __       _\n"
   "  |  \\/  |___  __| |_ " BLUE "(_)" NRM BOLD "_ __  ___  \\ \\    / /__ _ _| |_____ _ _\n"
   "  | |\\/| / _ \\/ _| ' \\| | '  \\/ _ \\  \\ \\/\\/ / _ \\ '_| / / -_) '_|\n"
   "  |_|  |_\\___/\\__|_||_|_|_|_|_\\___/   \\_/\\_/\\___/_| |_\\_\\___|_|\n" NRM
   "                        Copyright (c) 2019 Adequate Systems, LLC.\n"
   "           @@@@@@                            All rights reserved.\n"
   "        @@@  @@  @@@\n"
   "     @@@    @@      @@@    " BOLD "Worker~ %.32s%s\n" NRM
   "    @@  @@@@@@@@@@@@  @@     BinBuiltOn" BLUE "..." NRM " %s %s\n"
   "   @@  @@  @@  @@  @@  @@    BinVersion" BLUE "..." NRM " " VERSIONSTR "\n"
   "   @@  @@  @@  @@  @@  @@    Connection" BLUE "..." NRM " %s:%hu\n"
   "   @@  @@  @@  @@  @@  @@    Check work" BLUE "..." NRM " %u seconds\n"
   "   @@  @@  @@  @@  @@  @@    Difficulty" BLUE "..." NRM " %u (%s)\n"
   "    @@@@@@@@@@@@@@@@@@@@\n"
   "      @@@          @@@     Starting up...\n"
   "         @@@@@@@@@@\n\n",
   Name ? Name : "", Name ? strlen(Name) > 32 ? "..." : "" : "",
   __DATE__, __TIME__, Hostaddr, Port, Interval, Difficulty,
   Difficulty == 255 ? "automatic" : Difficulty > 0 ? "manual" : "host");

   /**
    * Enjoy the header for a moment */
   sleep(2);
   
   /**
    * Start the worker*/
   worker(Hostaddr);

   /**
    * End */
   printf("\n\nWorker exiting...\n\n");
   return 0;
} /* end main() */
