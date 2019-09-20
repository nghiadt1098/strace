#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <sys/signal.h>
#include <time.h>
#include "reg64.h"
#include "color.h"
#include <sys/prctl.h>
#include <linux/seccomp.h>

char FLAG_CHARSET[] = "0123456789abcdef";
#define FLAG_LENGTH 32
#define FLAG_FORMAT "FUSEC"
char * flag;

#define LOG_PATH "./log.txt"
#define DATA_PATH "/var/tmp/syscall64.txt"

const int long_size = sizeof(long);
typedef struct Syscall {
   char *name;
   int nargs;
   int isaddr[6];

} SyscallInfo;
//Get Register value
long getValue(pid_t child,int code);
//Set data of child process
void putdata(pid_t child, long addr,char *buffer, int len);
//Get data from child process
void getdata(pid_t child, long addr,char *buffer, int len);

char * genFlag();
SyscallInfo * loadSyscallList(int * numSyscall);
static void install_seccomp() {
  static unsigned char filter[] =  {32,0,0,0,4,0,0,0,21,0,0,18,62,0,0,192,32,0,0,0,0,0,0,0,53,0,16,0,0,0,0,64,53,0,15,0,77,1,0,0,21,0,13,0,66,1,0,0,21,0,12,0,57,0,0,0,21,0,11,0,58,0,0,0,21,0,10,0,16,0,0,0,21,0,9,0,56,0,0,0,21,0,8,0,85,0,0,0,21,0,7,0,4,0,0,0,21,0,6,0,88,0,0,0,21,0,5,0,10,1,0,0,21,0,4,0,217,0,0,0,21,0,3,0,78,0,0,0,21,0,2,0,216,0,0,0,21,0,1,0,40,0,0,0,6,0,0,0,0,0,255,127,6,0,0,0,57,5,5,0,6,0,0,0,0,0,0,0};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}


int main(int argc,char ** argv)
{
  if (argc<2){
    printf("<br>Usage: %s <path_to_elf><br>",argv[0]);
    exit(-1);
  }
  int elffd=open(argv[1],O_RDONLY);
  char buff[5];
  read(elffd,buff,5);
  if (buff[4]!='\x02'){
  	printf("<br>64 bit program only<br>");
  	exit(-1);
  }
  pid_t child=1;
  child=fork();
  if (child==0){
    ptrace(PTRACE_TRACEME,NULL,0,0);
    //install_seccomp(); <--- Warning! For SVATTT Final only
    execl(argv[1],"", NULL);
    exit(-1);
  } 
  else{

    flag=genFlag();
    FILE *f=fopen("/var/tmp/flag","w");
    fwrite(flag,strlen(flag),1,f);
    fclose(f);
    alarm(1);
    long syscallId=0;
    long arg[6]={0};
    int wstatus;
    int numSyscall;
    long retValue;
    time_t rawtime;
    struct tm * timeinfo;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
    dprintf(fd,"<br>"ANSI_COLOR_BYELLOW"Current local time and date:"ANSI_COLOR_RESET ANSI_COLOR_BBLUE" %s<br>"ANSI_COLOR_RESET, asctime (timeinfo) );
    dprintf(fd,ANSI_COLOR_BCYAN"NEW SESSION"ANSI_COLOR_RESET"<br>");
    //close(fd);
    SyscallInfo * list=loadSyscallList(&numSyscall);
    char* syscallStatus=calloc(numSyscall+1,1);
    while(1) {

      wait(&wstatus);
      if (WIFEXITED(wstatus)) {
        int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
        dprintf(fd,"<br>"ANSI_COLOR_BCYAN"Exited, status=%d"ANSI_COLOR_RESET"<br>", WEXITSTATUS(wstatus));
        //close(fd);
        break;
      } else if (WIFSIGNALED(wstatus)) {
        int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
        dprintf(fd,"<br>"ANSI_COLOR_BCYAN"Killed by signal %d"ANSI_COLOR_RESET"<br>", WTERMSIG(wstatus));
        //close(fd);
        break;
      } else if (WIFSTOPPED(wstatus)) {
        int sig_id=WSTOPSIG(wstatus);
        switch(sig_id){
          case SIGTRAP :
            break;
          case SIGSEGV :{
            int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
            dprintf(fd,"<br>"ANSI_COLOR_BCYAN"Stopped by signal %d"ANSI_COLOR_RESET ANSI_COLOR_BRED"SIGSEGV"ANSI_COLOR_RESET"<br>", WSTOPSIG(wstatus));
            //close(fd);
            exit(EXIT_SUCCESS);
            break;     
          }     
          default:{
            int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
            dprintf(fd,"<br>"ANSI_COLOR_BCYAN"Stopped by signal %d"ANSI_COLOR_RESET"<br>", WSTOPSIG(wstatus));
            //close(fd);
            exit(EXIT_SUCCESS);
            break;     
          }  
          exit(EXIT_SUCCESS);
        }

        
      }
      //Get syscall number
      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, child, NULL, &regs);

      syscallId=getValue(child,ORIG_RAX);
      retValue=getValue(child,RAX);
      arg[0]=getValue(child,RDI);
      arg[1]=getValue(child,RSI);
      arg[2]=getValue(child,RDX);
      arg[3]=getValue(child,R10);
      arg[4]=getValue(child,R8);
      arg[5]=getValue(child,R9);
      if (syscallId>=numSyscall){
        continue;
      }
      int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
      //close(fd);
      if (syscallStatus[syscallId]==1){
        //Hook after trigger syscall
        
        if (syscallId>numSyscall && syscallId<0){
          exit(-1);
        }
        syscallStatus[syscallId]=0;
        int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );
        dprintf(fd,"Syscall id %ld " ,syscallId);
        switch (syscallId){
          case SYS_openat:{
              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              char * filename=(char *)malloc(256);
              getdata(child,arg[1],filename,256);
              dprintf(fd,"0x%lx,\"%s\",0x%lx,0x%lx",arg[0],filename,arg[2],arg[3]);
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(filename);
          	}
          	break;

          case SYS_open: {
              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              char * filename=(char *)malloc(256);
              getdata(child,arg[0],filename,256);

              dprintf(fd,"\"%s\",0x%lx",filename,arg[1]);
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(filename);
            }
            break;

          case SYS_read:{
              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              short size=arg[2]+sizeof(long);//plus sizeof(long) so you can't overflow me now LuL

              char * buf=(char *)malloc(size);
              //if FD is not valid then take data from heap.
              if((signed long)retValue<0){
              	putdata(child,arg[1],buf,arg[2]);
              } 
              getdata(child,arg[1],buf,arg[2]);
              dprintf(fd,"%lu,0x%lx=\"",arg[0],arg[1]);
              write(fd,buf,arg[2]);
              dprintf(fd,"\",%lu",arg[2]);
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(buf);
            }
            break;
          case SYS_write:{
              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              short  size=arg[2]+sizeof(long);//plus sizeof(long) so you can't overflow me now LuL
              char * buf=(char *)malloc(size);
              getdata(child,arg[1],buf,arg[2]);
              //if FD is not valid then take data from heap.
              if((signed long)retValue<0){
              	putdata(child,arg[1],buf,arg[2]);
              }
              dprintf(fd,"%lu,0x%lx=\"",arg[0],arg[1]);
              write(fd,buf,arg[2]);
              dprintf(fd,"\",%lu",arg[2]);

              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(buf);
            }
            break;
          
          //Black List
          case SYS_fork:
          case SYS_vfork:
          case SYS_clone:
          case SYS_creat:
          case SYS_symlink:
          case SYS_symlinkat:
          case SYS_getdents64:
          case SYS_getdents:
            {
              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              int i;
              //Parse variable
              for (i=0;i<list[syscallId].nargs-1;++i){
                dprintf(fd,"0x%lx",arg[i]);
                if (list[syscallId].isaddr[i]){
                  char * data=(char *)malloc(256);
                  data[255]='\0';
                  getdata(child,arg[i],data,256);
                  dprintf(fd,"=\"%s\"",data);
                  free(data);
                } 
                dprintf(fd,",");
              }
              if (list[syscallId].isaddr[list[syscallId].nargs-1]){
                char * data=(char *)malloc(256);
                getdata(child,arg[list[syscallId].nargs-1],data,256);
                data[255]='\0';
                dprintf(fd,"=\"%s\"",data);
              } else {
                dprintf(fd,"0x%lx",arg[i]);
              }
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              puts(flag);
              kill(child,SIGABRT  );
              exit(EXIT_SUCCESS);
            }      
          //Black list with style
          case SYS_execveat:{

              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              char * buf=(char *)malloc(256);
              getdata(child,arg[1],buf,256);
              dprintf(fd,"0x%lu,\"%s\",0x%lx,0x%lu,0x%lu",arg[0],buf,arg[2],arg[3],arg[4]);
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(buf);
              puts(flag);
              kill(child,SIGABRT  );
              exit(EXIT_SUCCESS);
            break;
            }
          case SYS_execve:{

              dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
              char * buf=(char *)malloc(256);
              getdata(child,arg[0],buf,256);
              dprintf(fd,"\"%s\",0x%lx,0x%lu",buf,arg[1],arg[2]);
              dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
              free(buf);
              puts(flag);
              kill(child,SIGABRT  );
              exit(EXIT_SUCCESS);
            }
            break;
          default: 
            //Log it
            
            dprintf(fd,ANSI_COLOR_BRED"%s"ANSI_COLOR_RESET ANSI_COLOR_BYELLOW"("ANSI_COLOR_RESET,list[syscallId].name);
            int i;
            //Parse variable
            for (i=0;i<list[syscallId].nargs-1;++i){
              dprintf(fd,"0x%lx",arg[i]);
              if (list[syscallId].isaddr[i]){
                char * data=(char *)malloc(256);
                data[255]='\0';
                getdata(child,arg[i],data,256);
                dprintf(fd,"=\"%s\"",data);
                free(data);
              } 
              dprintf(fd,",");
            }
            if (list[syscallId].isaddr[list[syscallId].nargs-1]){
              char * data=(char *)malloc(256);
              getdata(child,arg[list[syscallId].nargs-1],data,256);
              data[255]='\0';
              dprintf(fd,"=\"%s\"",data);
            } else {
              dprintf(fd,"0x%lx",arg[i]);
            }
            dprintf(fd,ANSI_COLOR_BYELLOW")"ANSI_COLOR_RESET" = \t 0x%lx<br>",retValue);
            
        }
        //close(fd);

      } else {
        //Hook before trigger syscall
        int fd =1;//int fd=open(LOG_PATH,O_APPEND | O_WRONLY );

        syscallStatus[syscallId]=1;
        switch(syscallId){
          //Some hijack for our commponents
          case SYS_openat:{
            char * filename=(char *)malloc(256);
            getdata(child,arg[1],filename,256);
            if (strstr(filename,"flag")){
              putdata(child,arg[1],"/var/tmp/flag",sizeof("/var/tmp/flag\x00"));
            }
            free(filename);
            break;
          }
          case SYS_open:{
            char * filename=(char *)malloc(256);
            getdata(child,arg[0],filename,256);
            if (strstr(filename,"flag")){
              putdata(child,arg[0],"/var/tmp/flag\x00",sizeof("/var/tmp/flag\x00"));
            }
            free(filename);
            break;
          }

        }
      }
      
      ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
    for (int i=0;i< numSyscall;++i){
      free(list[i].name);
    }
    free(list);
    //close(fd);
  }

  exit(EXIT_SUCCESS);
  return 0;
}

long getValue(pid_t child,int code){
  return (long)ptrace(PTRACE_PEEKUSER, child, 8  * code, NULL);
}
void setValue(pid_t child,int code,long data){
  ptrace(PTRACE_POKEUSER, child, long_size  * code, data);
}
SyscallInfo * loadSyscallList(int * numSyscall){
  SyscallInfo * res=(SyscallInfo *)malloc(sizeof(SyscallInfo));
  FILE * f=fopen(DATA_PATH,"r");
  char * line=(char *) malloc(256);
  long len;
  int index;
  int na;
  int isar[6];
  while(feof(f)==0){
    getline(&line, &len, f);
    char * scName=malloc(256);
    sscanf(line,"%d %d %d %d %d %d %d %d %s",&index,&na,&isar[0],&isar[1],&isar[2],&isar[3],&isar[4],&isar[5],scName);
    res[index].name=scName;
    res[index].nargs=na;
    memcpy(&res[index].isaddr,&isar,sizeof(res[index].isaddr));
    //printf("%d %d %d %d %d %d %d %d %s<br>",index,na,isar[0],isar[1],isar[2],isar[3],isar[4],isar[5],scName);
    res=realloc(res,(index+2)*sizeof(SyscallInfo));
  }
  free(line);
  *numSyscall=index+1;
  fclose(f);
  return res;
}
void putdata(pid_t child, long addr,
             char *buffer, int len)
{   
    char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = buffer;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * long_size, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * long_size,
                          NULL);
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * long_size, data.val);
    }
}

void getdata(pid_t child, long addr,
             char *buffer, int len)
{   memset(buffer,0,len);
    char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = buffer;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * long_size,
                          NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;

    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                          child, addr + i * long_size,
                          NULL);
        memcpy(laddr, data.chars, j);
    }
}

char * genFlag(){
  srand(time(0));
  char * flag=malloc(sizeof(FLAG_FORMAT)+FLAG_LENGTH+1);
  char * p=flag;
  memcpy(flag,FLAG_FORMAT,sizeof(FLAG_FORMAT));
  p+=sizeof(FLAG_FORMAT)-1;
  *p='{';
  ++p;
  int i=0;
  for (i =0;i<FLAG_LENGTH;++i){
    *p=FLAG_CHARSET[rand()%16];
    ++p;
  }
  *p='}';
  return flag;
}