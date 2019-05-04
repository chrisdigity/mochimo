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
#define NRM  "\x1B[0m"
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

#define VERSIONSTR "Version 0.5" YELLOW "~beta" NRM

/* Include everything that we need */
#include "config.h"
#include "sock.h"     /* BSD sockets */
#include "mochimo.h"

/* Prototypes */
#include "proto.h"
int pinklist(word32 ip) { return VEOK; }
int epinklist(word32 ip) { return VEOK; }
void stop_mirror(void) { /* do nothing */ }
#ifdef CUDANODE
extern int trigg_init_cuda(byte difficulty, byte *blockNumber);
extern void trigg_free_cuda();
extern char *trigg_generate_cuda(byte *mroot, unsigned long long *nHaiku);
#endif

/* Include global data . . . */
#include "data.c"       /* System wide globals  */
word32 Interval;        /* get_work() poll interval seconds */

/* Support functions  */
#include "error.c"      /* error logging etc.   */
#include "add64.c"      /* 64-bit assist        */
#include "crypto/crc16.c"
#include "crypto/crc32.c"      /* for mirroring          */
#include "rand.c"       /* fast random numbers    */

/* Server control */
#include "util.c"
#include "sock.c"       /* inet utilities */
#include "connect.c"    /* make outgoing connection        */
#include "call.c"       /* callserver() and friends        */
#include "str2ip.c"

/**
 * Clear run flag, Running on SIGTERM */
void sigterm(int sig)
{
   signal(SIGTERM, sigterm);
   Running = 0;
}

/* Send packet: set advertised fields and crc16.
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
   
   // clear result and begin with "0x"
   result[0] = '\0';
   strcat(result, next);
   // work backwards to find first value
   while(bnum[pos] == 0 && pos > 0) pos--;
   // convert/Store remaining data
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
   
   // get timestamp
   time_t t = time(NULL);
   struct tm tm = *localtime(&t);
   
   // return if there's nothing to print
   if(fmt == NULL) return;
   // print timestamp prefix
   printf("[%d-%02d-%02d %02d:%02d:%02d] ",            /* Format */
         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, /*  Date  */
         tm.tm_hour, tm.tm_min, tm.tm_sec);            /*  Time  */

   // print remaining data
   va_start(argp, fmt);
   vfprintf(stdout, fmt, argp);
   va_end(argp);
   // flush to stdout
   fflush(stdout);
}

/**
 * Return current milliseconds for timing functions */
long long getms() {
    struct timeval tv; 
    gettimeofday(&tv, NULL);
    long long milliseconds = tv.tv_sec*1000LL + tv.tv_usec/1000;
   
    return milliseconds;
}

/**
 * Initialize miner and allocate memory where appropriate */
int init_miner(byte *mroot, byte diff, byte *bnum)
{
   int initGPU;

   if(Trace)
      wprintf("initialize miner for block: 0x%s\n", bnum2hex(bnum));

   /* Create the solution state-space beginning with
    * the first plausible link on the TRIGG chain. */
   trigg_solve(mroot, diff, bnum);

#ifdef CUDANODE
   /* Initialize CUDA specific memory allocations
    * and check for obvious errors */
   initGPU = -1;
   initGPU = trigg_init_cuda(diff, bnum);
   if(initGPU==-1) {
      wprintf("%sError: Cuda initialization failed. Check nvidia-smi%s\n", RED, NRM);
      trigg_free_cuda();
      return VERROR;
   }
   if(initGPU<1 || initGPU>64) {
      wprintf("%sError: Unsupported number of GPUs detected -> %d%s\n", RED, initGPU, NRM);
      trigg_free_cuda();
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
   /* Free CUDA specific memory allocations */
   trigg_free_cuda();
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
 *    tx,            TX struct containing the received data.
 *    tx->cblock,    64 bit unsigned integer (little endian) containing the current blockchain height.
 *    tx->blocknum,  64 bit unsigned integer (little endian) containing the blocknumber to be solved.
 *    tx->len,       16 bit unsigned integer (little endian) containing the length (in bytes) of data stored in tx->src_addr.
 *    tx->src_addr,  byte array which contains at least 33 bytes of data...
 *       byte 0,     8 bit unsigned integer containing the required difficulty to be solved.
 *       byte 1-32,  32 byte array containing the merkle root to be solved.
 *       byte 33-48, 16 byte array of random data (used to seed workers differently, to avoid duplicate work)
 *    } 
 * Worker Function... */
int get_work(NODE *np, char *addr)
{
   int ecode = 0;

   // connect and retrieve work
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
 *    tx,            TX struct containing the sent data.
 *    tx->blocknum,  64 bit unsigned integer (little endian) containing the blocknumber of the solution.
 *    tx->len,       8 bit unsigned integer containing the value 65.
 *    tx->src_addr,  byte array containing 65 bytes of data...
 *       byte 0,     8 bit unsigned integer containing the difficulty of the solution.
 *       byte 1-32,  32 byte array containing the merkle root that was solved.
 *       byte 33-64, 32 byte array nonce used to solve the merkle root.
 * Worker Function... */
int send_work(BTRAILER *bt, char *addr)
{
   NODE node;
   int ecode = 0;

   // connect
   if(callserver(&node, Peerip) != VEOK) {
      wprintf("%sError: Could not connect to %s...%s\n", RED, addr, NRM); 
      return VERROR;
   }

   // setup work to send
   put64(node.tx.blocknum, bt->bnum);
   node.tx.src_addr[0] = bt->difficulty[0];
   memcpy(node.tx.src_addr+1,    bt->mroot, 32);
   memcpy(node.tx.src_addr+1+32, bt->nonce, 32);
   node.tx.len[0] = 65;

   // send
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
   time_t Wtime, Htime, Stime;
   long long hcount, last_hcount, hps, ahps, ms;
   word16 len;
   char *haiku;
   int i, j;
   
   // initialize...
   char status[10] = " No Work";  // ... worker status indicator
   char color[10] = NRM;   // ... output color
   byte Zeros[8] = {0};    // ... Zeros (comparison blocknumber)
   byte Mining = 0;        // ... mining state
   byte hdiff = 0;         // ... tracks solved/host difficulty
   byte once = 0;          // ... trigger worker output ONCE
   word32 solutions = 1;   // ... solution count
   char *metric[] = {      // ... metrics
       "H/s",
      "KH/s",
      "MH/s",
      "GH/s",
      "TH/s"
   };

   // initialise event timers
   Ltime = time(NULL);   // UTC seconds
   Wtime = Ltime - 1;    // get work timer
   Htime = Ltime;        // haikurate calc timer
   Stime = Ltime;        // start time

   // initialize block trailer height
   put64(bt.bnum, One);

   // initialize Running state
   Running = 1;
   
   // initialize Peerip
   if((Peerip = str2ip(addr)) == 0) {
      printf("%sError: Peerip is invalid, addr=%s%s\n", RED, addr, NRM);
      return VERROR;
   }

   /* Main miner loop */
   while(Running) {
      Ltime = time(NULL);

      if(Ltime >= Wtime) {
         
         // get work from host
         ms = getms();
         if(get_work(&node, addr) == VEOK) {
            
            tx = &node.tx;
            len = get16(tx->len);

            /* check data for new work
             * ...change to block number
             * ...change to difficulty
             * ...change to mroot        */
            if(cmp64(bt.bnum, tx->blocknum) != 0 ||
               hdiff != TRANBUFF(tx)[0] ||
               memcmp(bt.mroot, TRANBUFF(tx)+1, 32) != 0) {
               
               // free any miner variables
               if(Mining)
                  Mining = uninit_miner();
               
               /* new work received
                * ...update block number
                * ...update host difficulty
                * ...update mroot
                * ...update rand2() sequence (if supplied) */
               memcpy(bt.bnum, tx->blocknum, 8);
               hdiff = TRANBUFF(tx)[0];
               memcpy(bt.mroot, TRANBUFF(tx)+1, 32);
               if(len > 33)
                  srand2(get32(TRANBUFF(tx)+1+32),
                         get32(TRANBUFF(tx)+1+32+4),
                         get32(TRANBUFF(tx)+1+32+4+4));
               
               // switch difficulty handling to auto if manual too low
               if(Difficulty != 0 && Difficulty < hdiff) {
                  wprintf("%sSpecified Difficulty is lower than required! (%d < %d)%s\n",
                          RED, Difficulty, hdiff, NRM);
                  wprintf("%sCanging difficulty to auto...%s\n", YELLOW, NRM);
                  Difficulty = 0;
               }
               // auto difficulty handling
               if(Difficulty == 0)
                  bt.difficulty[0] = hdiff;
               // manual difficulty handling
               else bt.difficulty[0] = Difficulty;

               /* test for "start miner" conditions
                * ...block number cannot be Zero
                * ...miner initialization must be successful */
               if(cmp64(bt.bnum, Zeros) == 0) {
                  strcpy(status, "No Work ");
                  strcpy(color, YELLOW);
                  once = 1;
               } else if(init_miner(bt.mroot, bt.difficulty[0], bt.bnum) == VEOK) {
                  strcpy(status, "New Work");
                  strcpy(color, NRM);
                  Mining = 1;
               } else {
                  strcpy(status, "InitFail");
                  strcpy(color, RED);
               }
            }
         }
         ms = getms() - ms;
         
         // perform haikurate calculations
         if((Htime = time(NULL) - Htime) == 0)
            Htime = 1;
         // use previous haikurate in averaging calculation
         ahps = ((ahps * 2) + (hcount / (long long)Htime)) / 3;
         // buff haikurate for cast to float
         hps = 100 * ahps;
         // get haikurate metric
         for(i = 0; i < 4; i++) {
            if(hps < 100000) break;
            hps = hps / 1000;
         }
         // Reset Haiku/s counters
         hcount = 0;
         Htime = time(NULL);
         
         if(cmp64(bt.bnum, One) > 0 || once) {
            if(once) once = 0;
            wprintf("%s%s | %s | rdiff=%d | %.02f %s [%lldms]%s\n",
                     color, status, bytes2hex_trim(bt.bnum), hdiff,
                     ((float) hps) / 100, metric[i], ms, NRM);
            if(Trace) {
               printf("  Lseed2=0x%08X | Lseed3=0x%08X | Lseed4=0x%08X\n",
                      Lseed2, Lseed3, Lseed4);
               printf("  mroot=");
               for(i = 0; i < 32; i++)
                  printf("%02X", bt.mroot[i]);
               printf("\n");
            }
            
            // set status to solving
            strcpy(status, "Solving ");
            strcpy(color, NRM);
         }
         
         // speed up polling if network is paused
         Wtime = time(NULL) + (cmp64(bt.bnum,Zeros) != 0 ? Interval : Interval/10);
      }

      // do the thing
      if(Mining) {

#ifdef CUDANODE
         haiku = trigg_generate_cuda(bt.mroot, &hcount);
#endif
#ifdef CPUNODE
         haiku = trigg_generate(bt.mroot, bt.difficulty[0]);
         hcount++;
#endif

         // Dynamic sleep function
         if(last_hcount == hcount)
            usleep(Dynasleep);
         else last_hcount = hcount;
         // Block Solved?
         if(haiku != NULL) {
            // Mmmm... Nice solution
            printf("\n%s\n\n", haiku);
            // ... better double check solution before sending
            if(!trigg_check(bt.mroot, bt.difficulty[0], bt.bnum))
               wprintf("%sError: The Mochimo gods have rejected your solution :(%s\n", RED, NRM);
            else {
               // Block SOLVED!
               // Offer solution to the gods
               ms = getms();
               for(i = 4, j = 0; i > -1; i--) {
                  if(send_work(&bt, addr) != VEOK) {
                     sleep(5);
                     continue;
                  }
                  ms = getms() - ms;
                  // find solution difficulty
                  while(trigg_check(bt.mroot, (byte)j, bt.bnum)) j++;
                  wprintf("%sSolution | %s | sdiff=%d | sols=%u [%lldms]%s\n",
                           GREEN, bytes2hex_trim(bt.bnum), j-1,
                           solutions++, ms, NRM);
                  break;
               }
               if(i < 0)
                  wprintf("%sFailed to send solution to host :(%s\n", RED, NRM);
            }
            // reset solution
            haiku = NULL;
            Wtime = Ltime - 1;
            put64(bt.bnum, One);
         }
      } else // Chillax if not Mining
         usleep(1000000);

   } /* end while(Running) */

   return VEOK;
}


void usage(void)
{
   printf("usage: worker [-option...]\n"
          "         -aS        set proxy ip to S\n"
          "         -pN        set proxy port to N\n"
          "         -iN        set polling interval to N\n"
          "         -dN        set difficulty to N\n"
          "         -tN        set Trace to N (0, 1)\n"
          "         -v         turn on verbosity\n"
          "         -l         open mochi.log file\n"
          "         -lFNAME    open log file FNAME\n"
          "         -e         enable error.log file\n"
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
   //Hostaddr;             // Default Host 127.0.0.1
   Port = Dstport = PORT1; // Default port 2095
   Interval = 20;          // Default get_work() interval seconds
   Difficulty = 0;         // Default difficulty (0 = auto)
   Dynasleep = 10000;
   
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
         default:   usage();
      }  /* end switch */
   }  /* end for j */
   
   /* Redirect signals */
   for(j = 0; j <= NSIG; j++)
      signal(j, SIG_IGN);
   signal(SIGINT, sigterm);  // signal interrupt, ctrl+c
   signal(SIGTERM, sigterm); // signal terminate, kill
   signal(SIGCHLD, SIG_DFL); // default signal handling, so waitpid() works
   
   /**
    * Introducing! */
   printf("\n"
          "          @@@@@@@@@          " BOLD  "  __  __         _    " BLUE "_" NRM "            __      __       _           \n" NRM
          "       @@@   @@    @@@       " BOLD  " |  \\/  |___  __| |_ " BLUE "(_)" NRM "_ __  ___  \\ \\    / /__ _ _| |_____ _ _ \n" NRM
          "    @@@     @@        @@@    " BOLD  " | |\\/| / _ \\/ _| ' \\| | '  \\/ _ \\  \\ \\/\\/ / _ \\ '_| / / -_) '_|\n" NRM
          "   @@  @@@@@@@@@@@@@@@  @@   " BOLD  " |_|  |_\\___/\\__|_||_|_|_|_|_\\___/   \\_/\\_/\\___/_| |_\\_\\___|_|  \n" NRM
          "  @@  @@   @@   @@   @@  @@  "       "  Copyright (c) 2019 Adequate Systems, LLC.  All rights reserved.\n"
          " @@   @@   @@   @@   @@   @@ "       "  " VERSIONSTR "            Built on %s %s\n"
          " @@   @@   @@   @@   @@   @@\n"
          " @@   @@   @@   @@   @@   @@   " ULINE "Worker Settings" NRM "\n"
          "  @@  @@   @@   @@   @@  @@  "       "  Connection" BLUE "..." NRM " %s:%hu\n"
          "   @@@@@@@@@@@@@@@@@@@@@@@   "       "  Check work" BLUE "..." NRM " %u seconds\n"
          "     @@@             @@@     "       "  Difficulty" BLUE "..." NRM " %u (%s)\n"
          "        @@@@@@@@@@@@@\n\n"

          "Initializing...\n\n", __DATE__, __TIME__, Hostaddr, Port, Interval, Difficulty,
          Difficulty > 0 ? "manual" : "auto");

   /**
    * Start the worker*/
   worker(Hostaddr);

   /**
    * End */
   printf("\n\nWorker exiting...\n\n");
   return 0;
} /* end main() */
