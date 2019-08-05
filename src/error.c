/* error.c  Error logging, trace, and fatal()
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 1 January 2018
 *
 * Error logging and trace functions
 *
*/

#ifdef WIN32
/* Define WIN32_LEAN_AND_MEAN and setup trigger to return definition to it's
 * original state to reduce undesired effects in the remaining codebase */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#define UNDEF_LEAN_AND_MEAN
#endif /* Not WIN32_LEAN_AND_MEAN */
#include <windows.h>
#ifdef UNDEF_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#undef UNDEF_LEAN_AND_MEAN
#endif /* UNDEF_LEAN_AND_MEAN */
#endif /* Not WIN32 */

#ifndef ERRORFNAME
#define ERRORFNAME "error.log"
#endif /* Not ERRORFNAME */
#ifndef LOGFNAME
#define LOGFNAME "mochi.log"
#endif /* Not LOGFNAME */
#ifndef COLORS
#define COLORS
#ifndef FOREGROUND_RED
#define FOREGROUND_RED 4
#endif /* Not FOREGROUND_RED */
#ifndef FOREGROUND_GREEN
#define FOREGROUND_GREEN 2
#endif /* Not FOREGROUND_GREEN */
#ifndef FOREGROUND_BLUE
#define FOREGROUND_BLUE 1
#endif /* Not FOREGROUND_BLUE */
#define WHITE   (RED | GREEN | BLUE)  /* 7 */
#define YELLOW  (RED | GREEN)         /* 6 */
#define MAGENTA (RED | BLUE)          /* 5 */
#define RED     FOREGROUND_RED        /* 4 */
#define CYAN    (GREEN | BLUE)        /* 3 */
#define GREEN   FOREGROUND_GREEN      /* 2 */
#define BLUE    FOREGROUND_BLUE       /* 1 */
#endif /* Not COLORS */


FILE *Logfp = NULL;
word32 Nerrors;      /* error counter */
char *Statusarg;     /* Statusarg->"message_string" shows on ps */


short get_console_color(void) {
#ifdef WIN32
   CONSOLE_SCREEN_BUFFER_INFO info;
   if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info))
      return info.wAttributes;
#endif
   return 0;
}


void set_console_color(short col) {
#ifdef WIN32
   HANDLE  hConsole;
   hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
   SetConsoleTextAttribute(hConsole, col);
#else
   col &= 0xF;
   switch(col) {
      case WHITE:   printf("\x1B[37m"); break;
      case YELLOW:  printf("\x1B[33m"); break;
      case MAGENTA: printf("\x1B[35m"); break;
      case RED:     printf("\x1B[31m"); break;
      case CYAN:    printf("\x1B[36m"); break;
      case GREEN:   printf("\x1B[32m"); break;
      case BLUE:    printf("\x1B[34m"); break;
      default:      printf("\x1B[0m");
   }
#endif
}

void log_time(FILE *fp)
{
   time_t curtime;

   time(&curtime);
   fprintf(fp, " on %s", asctime(gmtime(&curtime)));
   fflush(fp);
}

void log_time_short(FILE *fp)
{
   struct tm tm;
   time_t curtime;

   time(&curtime);
   tm = *localtime(&curtime);

   fprintf(fp, "[%d-%02d-%02d %02d:%02d:%02d] ",         /* Format */
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, /*  Date  */
           tm.tm_hour, tm.tm_min, tm.tm_sec);            /*  Time  */
}

/* Print an error message to error file and/or stdout
 * NOTE: errorfp is opened and closed on each call.
 */
int error(char *fmt, ...)
{
   va_list argp;
   FILE *errorfp;

   if(fmt == NULL) return VERROR;

   Nerrors++;
   errorfp = NULL;
   if(Errorlog) {
      errorfp = fopen(ERRORFNAME, "a");
   }
   if(errorfp != NULL) {
      fprintf(errorfp, "error: ");
      va_start(argp, fmt);
      vfprintf(errorfp, fmt, argp);
      va_end(argp);
      log_time(errorfp);
   }
   if(Logfp != NULL) {
      fprintf(Logfp, "error: ");
      va_start(argp, fmt);
      vfprintf(Logfp, fmt, argp);
      va_end(argp);
      log_time(Logfp);
   }
   if(!Bgflag && errorfp != stdout) {
      fprintf(stdout, "error: ");
      va_start(argp, fmt);
      vfprintf(stdout, fmt, argp);
      va_end(argp);
      log_time(stdout); 
   }
   if(errorfp != NULL) {
      fclose(errorfp);
   }
   return VERROR;
}


/* Print message to log file, Logfp, and/or stdout */
void plog(char *fmt, ...)
{
   va_list argp;

   if(fmt == NULL) return;

   if(Logfp != NULL) {
      va_start(argp, fmt);
      vfprintf(Logfp, fmt, argp);
      va_end(argp);
      log_time(Logfp);
   }
   if(!Bgflag && Logfp != stdout) {
      va_start(argp, fmt);
      vfprintf(stdout, fmt, argp);
      va_end(argp);
      log_time(stdout);
   }
}


/* Print colored message to log file, Logfp, and/or stdout 
 * prefixed with a short timestamp */
void splog(short color, char *fmt, ...)
{
   va_list argp;
   short col, tcol;

   if(fmt == NULL) return;

   if(Logfp != NULL) {
      log_time_short(Logfp);
      va_start(argp, fmt);
      vfprintf(Logfp, fmt, argp);
      va_end(argp);
      fflush(Logfp);
   }
   if(!Bgflag && Logfp != stdout) {
      log_time_short(stdout);
      va_start(argp, fmt);
      col = get_console_color();
      tcol = (col & 0xFFF0) | color;
      if(tcol) set_console_color(tcol);
      vfprintf(stdout, fmt, argp);
      set_console_color(col);
      va_end(argp);
      fflush(stdout);
   }
}


/* Kill the miner child */
int stop_miner(void)
{
   int status = 0;

   if(Mpid == 0) return -1;
   kill(Mpid, SIGTERM);
   waitpid(Mpid, &status, 0);
   Mpid = 0;
   return status;
}


/* Display terminal error message
 * and exit with exitcode after reaping zombies.
 */
void fatal2(int exitcode, char *message)
{
   stop_miner();
   if(Sendfound_pid) kill(Sendfound_pid, SIGTERM);
#ifndef EXCLUDE_NODES
   stop_mirror();
#endif
   if(!Bgflag && message) {
      error("%s", message);
      fprintf(stdout, "fatal: %s\n", message);
   }
   /* wait for all children */
   while(waitpid(-1, NULL, 0) != -1);
#ifdef _WINSOCKAPI_
    if(Needcleanup)
       WSACleanup();
#endif
   exit(exitcode);
}

/* Display terminal error message
 * and exit with NO restart (code 0).
 */
#define fatal(mess) fatal2(0, mess)
#define pause_server() fatal2(0, NULL);

void restart(char *mess)
{
   unlink("epink.lst");
   stop_miner();
   if(Trace && mess != NULL) plog("restart: %s", mess);
   fatal2(1, NULL);
}

char *show(char *state)
{
   if(state == NULL) state = "(null)";
   if(Statusarg) strncpy(Statusarg, state, 8);
   return state;
}
