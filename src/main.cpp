#include <csignal>
#include <fcntl.h>
#include <sys/file.h>

#include "nfqfilter.h"
//----------------------------------------------------------------------------

#define MAX_THREADS 15
#define DEF_SEG_FILE "/www/nfqueue.seg"
#define IRESPON_FILE "/tmp/log/nfqueue"
#define APP_PID_FILE "/tmp/run/nfqueue.pid"
#define PID_DIG_FILE "/tmp/run/diagnostic.pid"
//----------------------------------------------------------------------------

void saveProcessPID(pid_t pId)
{
    FILE *pFile = fopen(APP_PID_FILE,"wb+");

    if (pFile != NULL)
    {
        if (pId > 0)
            fprintf(pFile,"%d",pId);
        else
        {
            pId = getpid();
            fprintf(pFile,"%d",pId);
        }

        fclose(pFile);
    }
}
//----------------------------------------------------------------------------

int getPidFromFile()
{
    int line_length = 0;
    char line[128] = {0};
    FILE *pFile = fopen(PID_DIG_FILE,"r");

    if (pFile != NULL)
    {
        if (fgets(line,127,pFile) != NULL)
        {
            line_length = strlen(line);
            if (line[line_length-1] == '\n')
            {
                line[line_length-1] = 0;
                line_length--;
            }
        }

        fclose(pFile);
    }
    else
        NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Unable to open diagnostic pid file %s",PID_DIG_FILE);

    return (line_length <= 0) ? -1 : atoi(line);
}
//----------------------------------------------------------------------------

void createResponseFile(int error)
{
    FILE *pFile = fopen(IRESPON_FILE,"wb+");

    if (pFile == NULL)
        NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Unable to create response file");
    else
    {
        fprintf(pFile,"{\"error\": %d}",error);
        fclose(pFile);
    }
}
//----------------------------------------------------------------------------

void signalHandler(int sigNum)
{
    switch (sigNum)
    {
        case SIGINT:
        case SIGTERM:
                NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Attending terminate program call. Terminating nfqueue operations...");
                NFQDns::stopDnsService();
        break;
        case SIGABRT:
                NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Program abort. Some configurations are wrong...");
                createResponseFile(-3);
        break;
        case SIGSEGV:
                int result = -1;
                int procPid = getPidFromFile();

                NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Segmentation fault. Try to call diagnostic...");
                createResponseFile(-2);

                if (procPid != -1)
                    result = kill(procPid,SIGUSR1);  // Send signal to diagnostic process.

                // If error. Then nothing re-invoke NFQueue. Save Fatal segmentation file.
                if (procPid == -1 || result == -1)
                {
                    char com[64] = {0};

                    sprintf(com,"touch %s",DEF_SEG_FILE);
                    if (SysUtils::fileExists(DEF_SEG_FILE) == 0)
                        system(com);
                }
        break;
    }

    remove(APP_PID_FILE);
    exit(-1);
}
//----------------------------------------------------------------------------

void parseCmdLine(int argc, char **argv, string &file, unsigned char &bandwidth,
                  int &threads, bool &enabled, bool &demonize)
{
    file     = "";
    enabled  = false;
    demonize = false;
    threads  = MAX_THREADS;

    switch (argc)
    {
        case 6:
                if (tolower(argv[5][0]) == 'd')
                    demonize = true;
        case 5:
                try
                {
                    threads = AnsiStr::strToNum <int>(argv[4]);
                    threads = (threads > MAX_THREADS) ?  MAX_THREADS : threads;
                }
                catch(...) {
                    NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Invalid threads value. Use only one thread");
                    threads = 1;
                }
        case 4:

                if (strcmp(argv[3],"1") == 0)
                    enabled = true;

                if (!strcmp(argv[2],"0") || !strcmp(argv[2],"1") || !strcmp(argv[2],"2"))
                    bandwidth = argv[2][0] - 48;
                else {
                    NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Invalid bandwidth param. Not apply bandwidth management");
                    bandwidth = 0;
                }

                file = argv[1];
        break;
        default: NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Invalid params. Use:");
                 NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"                     1.- Path to configuration file");
                 NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"                     2.- Apply bandwidth. 0 or 1 or 2");
                 NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"                     3.- Apply defaults.  1 or 0");
                 NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"                     4.- Max threads to use. The max are 15");
                 NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"                     5.- Demonize app. Use d|D to demonize");
                 exit(-1);
    }
}
//----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    pid_t pId;
    int rCode;
    int threads;
    bool enabled;
    bool demonize;
    string configFile;
    unsigned char bandwidth;
    vector <BWData> bwDevices;

    try
    {
        NFQLogger::initLog("nfqueue");
        if (SysUtils::fileExists(APP_PID_FILE)) {
            NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Another instance still running. Aborting ...");
            return -1;
        }

        parseCmdLine(argc,argv,configFile,bandwidth,threads,enabled,demonize);

        if (demonize)
        {
            pId = fork();    // Create child process and check for valid pId.
            if (pId < 0)  {
                NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Error when create a child process.");
                return pId;
            }

            if (pId != 0) {
                saveProcessPID(pId);
                exit(0);
            }

            umask(2);
            if (setsid() == -1)
            {
               NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Error creating new session for child process. Aborting");
               remove(APP_PID_FILE);
               exit(-1);
            }
        }
        else
            saveProcessPID(0);

        signal(SIGINT,signalHandler);
        signal(SIGABRT,signalHandler);
        signal(SIGTERM,signalHandler);
        signal(SIGSEGV,signalHandler);

        NFQueue   queue(0,AF_INET);
        NFQFilter qFilter(configFile,enabled,threads);

        rCode = qFilter.loadConfigurationsFromFile(bandwidth,bwDevices);

        if (rCode != 0 && enabled)
            rCode = NFQBandwidth::applyBandwidth(bwDevices,bandwidth);

        createResponseFile(rCode);  // Create reponse file with response code ok or error. File used by interface.
        qFilter.addQueue(&queue);   // Add a queue object to administrate.

        NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Amount of memory used: QUEUE SIZE: %u "
                                               "SOCKET BUFFER: %u TOTAL MEM: %llu\n",queue.getQueueSize(),
                                               queue.getSocketBufferSize(),NFQueue::getTotalMemUsed());

        qFilter.run();
    }
    catch (std::exception &e) { NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Error in main catch: %s\n",e.what()); }
    catch (...)               { NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Unknow error main catch\n");          }

    remove(APP_PID_FILE);
    return 0;
}
//----------------------------------------------------------------------------
