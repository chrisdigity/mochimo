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

#define VERSIONSTR  "v0.4~BETA"   /*   as printable string */

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
byte Verbose;           /* Turns on worker output */
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
char *bnum2hex_trim(byte *bnum)
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
      wprintf("initialize miner for block: 0x%s", bnum2hex(bnum));

   /* Create the solution state-space beginning with
    * the first plausible link on the TRIGG chain. */
   trigg_solve(mroot, diff, bnum);

#ifdef CUDANODE

   /* Initialize CUDA specific memory allocations
    * and check for obvious errors */
   initGPU = -1;
   initGPU = trigg_init_cuda(diff, bnum);
   if(initGPU==-1) {
      wprintf("Error: Cuda initialization failed. Check nvidia-smi");
      trigg_free_cuda();
      return VERROR;
   }
   if(initGPU<1 || initGPU>64) {
      wprintf("Error: Unsupported number of GPUs detected -> %d",initGPU);
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
 *    Perform Mochimo Network three-way handshake
 *    Send OP code "Send Block" (OP_SEND_BL)
 *    Receive data -> {
 *       TX.Cblocknum = current blockchain height
 *       TX.blocknum = mining block
 *       TX.len = (1 byte)
 *       TX.src = difficulty of mined block (1 byte)
 *       TX.src+1 = merkle root (32 bytes)
 *       if(TX.len > 33)
 *          TX.src+33 = random seed (16 bytes)
 *    } */
int get_work(NODE *np, char *addr)
{
   int ecode = 0;

   // connect and retrieve work
   if(callserver(np, Peerip) != VEOK) {
      wprintf("Error: Could not connect to %s...", addr);
      return VERROR;
   }
   if(send_op(np, OP_SEND_BL) != VEOK) ecode = 1;
   if(!ecode && rx2(np, 1, 10) != VEOK) ecode = 2;
   if(!ecode && get16(np->tx.opcode) != OP_SEND_BL) ecode = 3;

   closesocket(np->sd);
   if(ecode) {
      wprintf("Error: get_work() failed with ecode(%d)", ecode); 
      return VERROR;
   }
   return VEOK;
}

/**
 * Send work to a node/pool.
 * Protocol...
 *    Perform Mochimo Network three-way handshake
 *    Assemble data -> {
 *       TX.blocknum = mined block (8 bytes)
 *       TX.len = 65 (1 byte)
 *       TX.src = difficulty of mined block (1 byte)
 *       TX.src+1 = merkle root (32 bytes)
 *       TX.src+33 = nonce/haiku (32 bytes)
 *    }
 *    Send OP code "Block Found" (OP_FOUND) */
int send_work(BTRAILER *bt, char *addr)
{
   NODE node;
   int ecode = 0;

   // connect
   if(callserver(&node, Peerip) != VEOK) {
      wprintf("Error: Could not connect to %s...", addr); 
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
      wprintf("Error: send_work() failed with ecode(%d)", ecode); 
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
   long long hcount, last_hcount, hps;
   long long acount, ahps, ms;
   word16 newseed, len;
   char *haiku;
   int i, j;

   // initialise event timers
   Ltime = time(NULL);   // UTC seconds
   Wtime = Ltime - 1;    // get work timer
   Htime = Ltime;        // haikurate calc timer
   Stime = Ltime;        // start time
   
   // initialize metrics
   char *metric[] = {
       "H/s",
      "KH/s",
      "MH/s",
      "GH/s",
      "TH/s"
   };
   
   // initialize Zeros (comparison blocknumber)
   byte Zeros[8] = {0,};
   
   // initialize mining state
   byte Mining = 0;

   // initialize block trailer height
   bt.bnum[0] = 1;

   // initialize Running state
   Running = 1;
   
   // check Peerip is valid
   if((Peerip = str2ip(addr)) == 0) {
      printf("Peerip is invalid, addr=%s", addr);
      return VERROR;
   }
   if(Verbose) {
      printf("Initialization settings...\n");
      printf("Host -> %s (%u)\n", addr, Peerip);
      printf("Port -> %hu\n", Port);
      printf("Poll -> %u\n\n", Interval);
   }

   /* Main miner loop */
   while(Running) {
      Ltime = time(NULL);

      if(Ltime > Wtime) {
         ms = getms();
         if(get_work(&node, addr) == VEOK) {
            ms = getms() - ms;
            
            tx = &node.tx;
            len = get16(tx->len);

            /* check data for new work
             * ...change to block number
             * ...change to difficulty
             * ...change to mroot        */
            if(cmp64(bt.bnum, tx->blocknum) != 0 ||
               bt.difficulty[0] != TRANBUFF(tx)[0] ||
               memcmp(bt.mroot, TRANBUFF(tx)+1, 32) != 0) {

               /* free any miner variables */
               if(Mining)
                  Mining = uninit_miner();

               /* new work received
                * ...update block number
                * ...update difficulty
                * ...update mroot
                * ...update rand2() sequence (if required) */
               memcpy(bt.bnum, tx->blocknum, 8);
               bt.difficulty[0] = TRANBUFF(tx)[0];
               memcpy(bt.mroot, TRANBUFF(tx)+1, 32);
               if(len > 33)
                  srand2(get16(TRANBUFF(tx)+1+32), 0, 0);

               /* test for "start miner" conditions
                * ...block number cannot be Zero
                * ...miner initialization must be successful */
               if(cmp64(bt.bnum, Zeros) == 0) {
                  if(Verbose)
                     wprintf("Received network pause...\n");
               } else if(init_miner(bt.mroot, bt.difficulty[0], bt.bnum) != VEOK) {
                  wprintf("\nError: Miner failes to initialize...\n\n");
               } else
                  Mining = 1;
            }
         }
         
         if(Verbose) {
            // perform immediate haikurate calculations
            if((Htime = time(NULL) - Htime) == 0)
               Htime = 1;
            hps = 100 * hcount / (long long) Htime;
            // get immediate haiku metric
            for(i = 0; i < 4; i++) {
               if(hps < 100000) break;
               hps = hps / 1000;
            }
            // perform alltime haikurate calculations
            if((Htime = time(NULL) - Stime) == 0)
               Htime = 1;
            acount += hcount;
            ahps = 100 * acount / (long long) Htime;
            // get alltime haiku metric
            for(j = 0; j < 4; j++) {
               if(ahps < 100000) break;
               ahps = ahps / 1000;
            }

            // Reset Haiku/s counters
            hcount = 0;
            Htime = time(NULL);

            // console output if network not paused
            if(cmp64(bt.bnum,Zeros) != 0) {
               wprintf("ping=%lldms | bnum=%s | diff=%d | i:%.02f %s | a:%.02f %s\n",
                       ms, bnum2hex_trim(bt.bnum), (int)bt.difficulty[0],
                       ((float) hps) / 100, metric[i], ((float) ahps) / 100, metric[j]);
               /* Removed info overload
               printf("  mroot=");
               for(i = 0; i < 32; i++)
                  printf("%02X", bt.mroot[i]);
               printf("\n"); */
            }
         }
         
         Wtime = time(NULL) + Interval;
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
            if(Verbose) {
               printf("\n%s\n\n", haiku);
               wprintf("Found Solution!\n");
            }
            // ... better double check solution before sending
            if(!trigg_check(bt.mroot, bt.difficulty[0], bt.bnum))
               wprintf("Error: The Mochimo gods have rejected your solution :(");
            else {
               // Block SOLVED!
               // Offer solution to the gods
               for(i = 4; i > -1; i--) {
                  if(send_work(&bt, addr) == VEOK) {
                     if(Verbose)
                        wprintf("Solution sent successfully!\n");
                     break;
                  }
                  if(Verbose)
                     wprintf("Solution failed to send... %d retries left\n\n", i);
                  sleep(5);
               }
            }
            // reset solution
            haiku = NULL;
            Wtime = Ltime - Interval;
            put64(bt.bnum, Zeros);
         }
      }

      // Chillax if not Mining
      if(!Mining) usleep(100000);

   } /* end while(Running) */

   return VEOK;
}


void usage(void)
{
   printf("usage: worker [-option...]\n"
          "         -aS        set proxy ip to S\n"
          "         -pN        set proxy port to N\n"
          "         -iN        set polling interval to N\n"
          "         -tN        set Trace to N (0, 1)\n"
          "         -v         turn on verbosity\n"
   );
   exit(0);
}


/**
 * Initialise data and call the worker */
int main(int argc, char **argv)
{
   static int j;
   static byte endian[] = { 0x34, 0x12 };
   static char *Pooladdr;

   /* sanity checks */
   if(sizeof(word32) != 4) fatal("word32 should be 4 bytes");
   if(sizeof(TX) != TXBUFFLEN || sizeof(LTRAN) != (TXADDRLEN + 1 + TXAMOUNT)
      || sizeof(BTRAILER) != BTSIZE)
      fatal("struct size error.\nSet compiler options for byte alignment.");    
   if(get16(endian) != 0x1234)
      fatal("little-endian machine required for this build.");

   srand16(time(&Ltime));       /* seed ID token generator */
   srand2(Ltime, 0, 0);
   
   /**
    * Set Defaults */
   Peerip = 0x0100007f;    // Default Host 127.0.0.1
   Interval = 20;          // Default get_work interval seconds
   Port = Dstport = PORT1; // Default port 2095
   
   
   /**
    * Parse command line arguments */
   for(j = 1; j < argc; j++) {
      if(argv[j][0] != '-') usage();
      switch(argv[j][1]) {
         case 'a':  if(argv[j][2]) Pooladdr = &argv[j][2];
                    break;
         case 'p':  Port = Dstport = atoi(&argv[j][2]);
                    break;
         case 'i':  if(argv[j][2]) Interval = atoi(&argv[j][2]);
                    break;
         case 't':  Trace = atoi(&argv[j][2]); /* set trace level  */
                    break;
         case 'v':  Verbose = 1; /* set verbosity  */
                    break;
         case 'l':  Logfp = fopen(LOGFNAME, "a"); /* open log file used by plog() */
                    break;
         case 'e':  Errorlog = 1;  /* enable "error.log" file */
                    break;
         default:   usage();
      }  /* end switch */
   }  /* end for j */

   /* Force some things */
   Dynasleep = 10000;

   /* Redirect signals */
   for(j = 0; j <= NSIG; j++)
      signal(j, SIG_IGN);
   signal(SIGINT, sigterm);  // signal interrupt, ctrl+c
   signal(SIGTERM, sigterm); // signal terminate, kill
 
   // Do I still need this?...v
   signal(SIGCHLD, SIG_DFL);  /* so waitpid() works */
   
   /**
    * Introducing! */
   printf("\nMochimo Worker %s - Built on %s %s\n"
          "Copyright (c) 2019 Adequate Systems, LLC.  All rights reserved.\n"
          "\nWorker Running...\n\n", VERSIONSTR, __DATE__, __TIME__);

   /**
    * Start the worker*/
   worker(Pooladdr);

   /**
    * End */
   printf("\n\nWorker exiting...\n\n");
   return 0;
} /* end main() */
