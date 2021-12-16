/*
* Author: Steven Au
* Title: smallsh
* Purpose: A small shell program that executes various features that are available in popular shells such as bash.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

// Maximum length of a command line entry and argument array length.
#define COMMANDLINELENGTH 2048
#define ARGUMENTLENGTH 512

// Global Variables
int foregroundOnly = 1;                // For background/foreground Control Z signal - Mod
int backflag = 0;                      // To identify whether the current command is in the background
int foregroundPids[COMMANDLINELENGTH]; // Track all foreground pids
int backgroundPids[COMMANDLINELENGTH]; // Track all background pids
int foregroundPidCount = 0;            // Count of the foreground pids
int backgroundPidCount = 0;            // Count of the background pids

/* void backgroundSwitch
* Purpose:      Switches the global flag between background and foreground per the signal sent via control z (SIGTSTP).
* Parameters:   int sig = Signal sent in by keyboard command
* Assumptions:  A background global flag is set to an integer.
* Returns:      None
*/
void backgroundSwitch(int sig)
{
    // Checks the background global flag and switch accordingly.
    if (foregroundOnly == 0)
    {
        write(STDOUT_FILENO, "\nEntering foreground-only mode (& is now ignored)\n", 51);
        foregroundOnly = 1; // Change flag
    }
    else
    {
        write(STDOUT_FILENO, "\nExiting foreground-only mode\n", 31);
        foregroundOnly = 0; // Change flag
    }
    // Whenever this signal is invoked, the new prompt line is not showing...
    write(STDOUT_FILENO, ": ", 2);
}

/* void interruptCheck
* Purpose:      For use with the control c - interrupt - signal. Prints the message accordingly (SIGINT)
* Parameters:   int sig = Signal sent in by keyboard command
* Assumption:   Signal is for the child process currently running in the foreground only - does not affect the parent and background processes.
* Returns:      None
*/
void interruptCheck(int sig)
{
    write(STDOUT_FILENO, "terminated by signal 2\n", 23);
}

/* entryParser
* Purpose:      Get user entry and adjust accordingly
* Parameters:   char *commandInput = the array for the command line entry
*               char **argVector = The array of command + argument entries (Called Vector in R programming)
*               pid_t pid = The parent process id number
* Returns:      int indexCounter = The count of the amount of arguments possible.
*/
int entryParser(char *commandInput, char **argVector, pid_t pid)
{
    char *saveptr = NULL;   // Inisitate the save pointer
    char *saveptr2 = NULL;  // Second pointer due to a segmentation fault
    int indexCounter = 0;   // Initiate the index counter for the argument vector count.

    // Stdin input command where first "word" is the command and the subsequent words are arguments.
    fgets(commandInput, COMMANDLINELENGTH, stdin);

    // Tokened the entire input from command line (Enter is recorded as a new line)
    char *tokened = strtok_r(commandInput, "\n", &saveptr);

    // If tokened is a null pointer, nullify the first entry and then end.
    if (tokened == NULL)
    {
        argVector[indexCounter] = NULL;
        return;
    }

    // Parse out the entire entry for any $$ signs and do variable expansion accordingly.
    pidParse(tokened, pid);

    char *token = strtok_r(tokened, " \0", &saveptr2);

    // As long as any token is not null
    while (token != NULL)
    {
        // Inject the entry
        argVector[indexCounter] = token;
        token = strtok_r(NULL, " \0", &saveptr2);
        indexCounter++; // And keep track of the count

        // Arguments cannot exceed 512 - break accordingly
        if (indexCounter == ARGUMENTLENGTH)
        {
            break;
        }
    }
    return indexCounter;
}

/* void pidParse
* Purpose:      Parses for the pid replacement per each instance of a double $$ accordingly to do variable expansion by injecting the pid.
* Parameters:   char *token = The string that is going to be parsed
*               pid_t pid = The parent process id number
* Returns:      None
*/
void pidParse(char *token, pid_t pid)
{
    // Track the token counts and length
    int tokenLength = strlen(token);

    // Stringify the pid
    char *pidString[COMMANDLINELENGTH];
    sprintf(pidString, "%d", pid);
    int pidLength = strlen(pidString);

    // Loop through each of the characters and check accordingly for $$
    for (int eachChar = 0; eachChar < tokenLength; eachChar++)
    {
        // If double $ - do variable expansion
        if ((token[eachChar - 1] == '$') && (token[eachChar] == '$'))
        {
            // Ensure a duplicate copy and replace the $$ locations with %d
            char *tokenContent = strdup(token);
            tokenContent[eachChar - 1] = '%';
            tokenContent[eachChar] = 'd';

            // for sprintf to inject the value
            sprintf(token, tokenContent, pid);
            tokenLength += pidLength; // Loop is increased by the pid length
        }
    }
}

/* cleanEntries
* Purpose:      Resets the entry values of the the argument vector to all null for new entries.
* Parameters:   char **argVector = The array of command + argument entries
*               int indexCounter = The count of number of arguments entered
* Returns:      None, the argument vector will be cleared per the pointer.
*/
void cleanEntries(char **argVector, int indexCounter)
{
    for (int index = 0; index < indexCounter; index++)
    {
        argVector[index] = NULL; // Replace the arguments in the vector accrodingly
    }
}

/* removeBackgroundPid
* Purpose:      Removes the current list of active background pids.
*               Due to how C programming removes items from an array, I've opted to zero out the value instead. The function "checkComplete" accomodates for the "0" values.
* Parameters:   pid_t checkPid = The processing id to be checked if it matches with the current background pids
* Returns:      None
*/
void removeBackgroundPid(pid_t checkPid)
{
    // Initiate for the waitpid
    int childStatus;
    pid_t spawnPid;

    // Loop though the existing backgroundPids list
    for (int eachPid; eachPid < backgroundPidCount; eachPid++)
    {
        spawnPid = waitpid(backgroundPids[eachPid], &childStatus, WNOHANG);

        // The checkpid matches with a background pid and that it is a "dead" process
        if (checkPid == backgroundPids[eachPid] && spawnPid == -1)
        {
            backgroundPids[eachPid] = 0; // Zero out the value accordingly.
        }
    }
}

/* checkComplete
* Purpose: Checks for the completed background processes. Then reaps and reports them accordingly.
*           This is due to the signal processing of control c causing an incorrect report of a "completed" process.
* Parameters: None
* Returns: None
*/
void checkComplete()
{
    // Inidiates
    pid_t spawnPid;
    int childStatus;
    int ignoreFlag = 0; // This is for any foreground process in record so they would not be reported.

    // Citation for the following function:
    // Date: 10/23/2021
    // https://man7.org/linux/man-pages/man2/wait.2.html
    // -1 means that it will check for any child process.
    spawnPid = waitpid(-1, &childStatus, WNOHANG);

    // If a pid was found
    while (spawnPid > 0)
    {
        // Check if it is within the foregroundPids list.
        for (int counter = 0; counter < foregroundPidCount; counter++)
        {
            // If this spawnPid was within the foreground pids.
            if (foregroundPids[counter] == spawnPid)
            {
                ignoreFlag = 1; // Add it to ignore
            }
        }
        // If there is an ignorable pid - reap it accordinly
        // This is due to an issue with signal termination and this function reporting a "foreground" termination as "background".
        if (ignoreFlag)
        {
            if (WIFEXITED(childStatus))
            {
                WEXITSTATUS(childStatus);
            }
            else if (WIFSIGNALED(childStatus))
            {
                WTERMSIG(childStatus);
            }
        }
        // For all background pids
        else
        {
            // Remove the background pid.
            removeBackgroundPid(spawnPid);
            // Then report the status of the background pid by how it ended: By exit or signal.
            if (WIFEXITED(childStatus))
            {
                printf("background pid %d is done: exit value %d\n", spawnPid, WEXITSTATUS(childStatus));
                fflush(stdout);
            }
            else if (WIFSIGNALED(childStatus))
            {
                printf("background pid %d is done: terminated by signal %d\n", spawnPid, WTERMSIG(childStatus));
                fflush(stdout);
            }
        }
        // Go to the next pid, if any, and report it accordingly.
        spawnPid = waitpid(-1, &childStatus, WNOHANG);
    }
}

/* backgroundCheck
* Purpose:      Adds Null to the end of the array accordingly. If the final entry is the background command & symbol,
*               then remove the symbol and mark background process accordingly.
*               (Note: I've wrote this function before the control z background process switch to use global variables.)
* Parameters:   char **argVector = The array of command + argument entries
*               int indexCounter = the count of number of arguments entered
*               int backAndFore = The background flag that is to be determined to be a 1 or 0. (This was implemented before the control z signal)
* Returns:      Int backAndFore = The updated background flag check
*/
int backgroundCheck(char **argVector, int indexCounter, int backAndFore)
{
    // Remove the final character if it is for the background.
    if (strcmp(argVector[indexCounter - 1], "&") == 0)
    {
        argVector[indexCounter - 1] = NULL; // Then nullify the space accordingly.
        backAndFore = 1;                    // Back and forth, well, foreground = fore.
    }
    // Nullify the final index in the vector for use with execvp.
    else
    {
        argVector[indexCounter] = NULL;
    }
    return backAndFore; // Retains or updates the background flag accordingly.
}

/* termPids
* Purpose:      Terminate all existing child processes on exit.
* Parameters:   None
* Returns:      None
*/
void termPids()
{
    // Cycles through all the pids
    for (int eachPid; eachPid < backgroundPidCount; eachPid++)
    {
        // If any are still "existing"
        if (backgroundPids[eachPid] > 0)
        {
            // Citation for the following function
            // Date: 10/27/2021
            // https://man7.org/linux/man-pages/man2/kill.2.html
            // Kill any other processes or jobs started.
            kill(backgroundPids[eachPid], SIGKILL);
        }
    }
}

/* exitProcess
* Purpose:      Conducts an exit per the built in command "exit." Runs the termPids function before exiting.
* Parameters:   None
* Returns:      None
*/
void exitProcess()
{
    termPids(); // Terminate each of the children...........
    exit(0);    // And then exit
}

/* void changeDir
* Purpose:      Changes the current working directory to the one specified by the user as the first argument within their command.
*               If no command was entered, then the user will be sent to the "Home" directory as indicated by their environment variable.
* Parameters:   char **argVector = The array of command + argument entries
* Returns:      None
*/
void changeDir(char **argVector)
{
    // Change directory to the Home environment variable if no argument.
    if (argVector[1] == NULL)
    {
        chdir(getenv("HOME")); // Go home per the home path variable and ends the function accordingly.
        return;
    }
    // Determine the change of directory if there is an argument - uses the first argument only.
    // Citation for the following function:
    // Date: 10/20/2021
    // https://man7.org/linux/man-pages/man2/chdir.2.html
    // -1 is returned from chdir() if there is an error.
    if (chdir(argVector[1]) == -1)
    {
        printf("No Such Directory Exists.\n"); // Does not exist
        fflush(stdout);
    }
    else
    {
        chdir(argVector[1]); // Directory exists, change accordingly.
    }
}

/* statusCheck
* Purpose:      Prints out either the exit status or the terminating signal of the last foreground process ran based on the childStatus variable.
* Parameters:   int childStatus = The most recent foreground status executed
* Returns:      None
*/
void statusCheck(int childStatus)
{
    // Citation for the following function:
    // Date: 10/24/2021
    // https://man7.org/linux/man-pages/man2/wait.2.html
    // WIFEXITED, WEXITSTATUS, WIFSIGNALED, and WTERMSIG - The status is checked and the appropriate message is parsed and returned accordingly.
    // Checks whether this was based on an exit or signal termination and print accordingly.
    if (WIFEXITED(childStatus))
    {
        printf("exit value %d\n", WEXITSTATUS(childStatus));
        fflush(stdout);
    }
    else if (WIFSIGNALED(childStatus))
    {
        printf("terminated by signal %d\n", WTERMSIG(childStatus));
        fflush(stdout);
    }
    return;
}

/* int execProcesses
* Purpose:      Execute non-built in commands based on the argument vector array data values. Then, reports the status accordingly.
* Parameters:   char **argVector = The array of command + argument entries
*               pid_t pid = The parent process id number.
*               int backflag = The background flag command (This function was written before implementing signals)
*               int indexCounter = The counter of argument entries
* Returns:      childStatus = the foreground status that was processed per the execvp function.
*/
int execProcesses(char **argVector, pid_t pid, int backflag, int indexCounter)
{
    char nullSource[10] = "/dev/null\0"; // The null space for background processes.
    char theInput[COMMANDLINELENGTH];    // The input
    char theOutput[COMMANDLINELENGTH];   // and output at the starting index are going to be null spaces.
    int childStatus;                     // Stat init
    int inputFlag = 0;                   // Mark if this is an input
    int outputFlag = 0;                  // or output

    pid_t spawnPid = fork();

    // Child process switch
    switch (spawnPid)
    {
    case -1:
        perror("Error trying to create a new process...");
        exit(1);
        break;
    case 0:
        // See the main function for the initialization - the process here is to replace the child process' flags.
        // Any children running as background processes must ignore SIGINT
        // A child running as a foreground process must terminate itself when it receives SIGINT
        if (!backflag)
        {
            // Therefore foreground processes will have the signal action changed.
            struct sigaction SIGINT_action = {0};
            SIGINT_action.sa_handler = interruptCheck; // Permit the interruption and print out a message accordingly
            sigfillset(&SIGINT_action.sa_mask);        // Block accordingly
            SIGINT_action.sa_flags = 0;                // No flags
            sigaction(SIGINT, &SIGINT_action, NULL);   // Inject the signal handler
        }

        // Any children running in the foreground or background process must ignore SIGTSTP.
        // Ignore Control Z
        struct sigaction SIGTSTP_action = {0};
        SIGTSTP_action.sa_handler = SIG_IGN;       // Ignore the signal
        sigfillset(&SIGTSTP_action.sa_mask);       // Block all other catchable signals
        SIGTSTP_action.sa_flags = 0;               // No flags
        sigaction(SIGTSTP, &SIGTSTP_action, NULL); // Inject the signal handler

        // Check all vector arguments for input redirection
        //  I am assuming that there is only one input and one output
        for (int theCheckCounter = 0; theCheckCounter < indexCounter; theCheckCounter++)
        {
            // Only one imput entry - this is the "first" and leftmost argument (EG: ls > junk > kunj : will only take in the first argument junk and not kunj)
            if (inputFlag == 0 && strcmp(argVector[theCheckCounter], "<") == 0)
            {
                argVector[theCheckCounter] = NULL; // Remove the argument - not passed into exec
                // If the user doesn't redirect the standard input for a background command, then standard input should be redirected to /dev/null
                if (argVector[theCheckCounter + 1] == NULL && backflag == 1)
                {
                    strcpy(theInput, nullSource); // dev/null-ed for background processes only.
                }
                else
                {
                    strcpy(theInput, argVector[theCheckCounter + 1]); // The next argument is assumed to what is needed - strcpy due to the above - this is a later function.
                }
                theCheckCounter++; // Increment accordingly to account for the additional +1 to argVector
                inputFlag = 1;     // Mark for input - only the one value will count
            }
            if (outputFlag == 0 && strcmp(argVector[theCheckCounter], ">") == 0)
            {
                argVector[theCheckCounter] = NULL; // Remove the argument - not passed into exec
                // If the user doesn't redirect the standard output for a background command, then standard output should be redirected to /dev/null
                if (argVector[theCheckCounter + 1] == NULL && backflag == 1)
                {
                    strcpy(theOutput, nullSource); // dev/null-ed for background processes only.
                }
                else
                {
                    strcpy(theOutput, argVector[theCheckCounter + 1]); // The next argument is assumed to what is needed - strcpy due to the above
                }
                theCheckCounter++; // Increment accordingly to account for the additional +1 to argVector
                outputFlag = 1;    // Mark for output - only the one value will count
            }
        }
        // If there is an input
        if (inputFlag)
        {
            // Open source file
            int sourceFD = open(theInput, O_RDONLY); // Read only
            if (sourceFD == -1)
            {
                // Cannot open - exit
                printf("cannot open %s for input\n", theInput);
                fflush(stdout);
                exit(1);
            }
            // Input redirection
            int result = dup2(sourceFD, STDIN_FILENO);  // Used STDIN_FILENO based on the assignment modules
            if (result == -1)
            {
                // Failed to open the file descriptor - exit
                printf("cannot open %s for input\n", theInput);
                fflush(stdout);
                exit(1);
            }
        }
        // If there is an output
        if (outputFlag)
        {
            // Open target file
            // Write only, create if nonexistent, and truncate if exists. Permissions Lucky 7 opened to all.
            int targetFD = open(theOutput, O_WRONLY | O_CREAT | O_TRUNC, 0777);
            if (targetFD == -1)
            {
                // Cannot open - exit
                printf("cannot open %s for output\n", theOutput);
                fflush(stdout);
                exit(1);
            }
            // Output redirection
            int result = dup2(targetFD, STDOUT_FILENO);  // Used STDOUT_FILENO based on the assignment modules
            if (result == -1)
            {
                // Failed to open the file descriptor - exit
                printf("cannot open %s for output\n", theOutput);
                fflush(stdout);
                exit(1);
            }
        }

        // Exexute accordingly
        execvp(argVector[0], argVector);
        // exec only returns if there is an error
        printf("%s: no such file or directory\n", argVector[0]);
        fflush(stdout);
        exit(1);
        break;
    default:
        // In the parent process
        // If this is a background process
        if (backflag)
        {
            // Track the bg pid
            backgroundPids[backgroundPidCount] = spawnPid;
            backgroundPidCount++;

            // Notify and not hang around...
            printf("background pid is %d\n", spawnPid);
            fflush(stdout);
            waitpid(spawnPid, &childStatus, WNOHANG);
        }
        // Foreground process
        else
        {
            // Wait for child's termination
            // Ensures print message by matching with the child process (Child process "spawnpid 0" does not print out message when interrupted)
            // Any children running as background processes must ignore SIGINT
            // A child running as a foreground process must terminate itself when it receives SIGINT
            struct sigaction SIGINT_action = {0};
            SIGINT_action.sa_handler = interruptCheck;
            sigfillset(&SIGINT_action.sa_mask);
            SIGINT_action.sa_flags = SA_RESTART;
            sigaction(SIGINT, &SIGINT_action, NULL); // Inject the signal handler

            // Track the foreground pid for reaping purposes and hang around.
            foregroundPids[foregroundPidCount] = spawnPid;
            foregroundPidCount++;
            waitpid(spawnPid, &childStatus, 0);
        }
        break;
    }
    // Return the status for the "status" command.
    return childStatus;
}

/* void main
* Purpose:      The main processing of the smallsh program
* Parameters:   None
* Assumptions:  None
* Returns:      None
*/
void main()
{
    // General syntax: command [arg1 arg2 ...] [< input_file] [> output_file] [&]
    char *commandInput[COMMANDLINELENGTH];        // Store user entry command inputs and arguments as a raw stdin
    char *argVector[ARGUMENTLENGTH];              // Parse entry and convert into a vector of strings - command + [Arguments]
    int indexCounter = 0;                         // Counts the arguments in the argument vector
    int childStatus = 0;                          // For use with the "status" command.
    pid_t pid = getpid();                         // Process ID

    // Generate the size needed for the arguments.
    for (int i = 0; i < ARGUMENTLENGTH; i++)
    {
        argVector[i] = malloc(sizeof(char) * COMMANDLINELENGTH);
    }

    // Ignore Control C - reset back to this state if there is a change due to a foreground child.
    struct sigaction SIGINT_action = {0};         // Initialize SIGINT_action struct to be empty
    SIGINT_action.sa_handler = SIG_IGN;           // Register SIGIGN - signal ignore
    sigfillset(&SIGINT_action.sa_mask);           // Block all other catchable signals
    SIGINT_action.sa_flags = SA_RESTART;          // The easier solution is using SA_RESTART flag in the signal handler
    sigaction(SIGINT, &SIGINT_action, NULL);      // Inject the signal handler

    // Control Z foreground signal
    struct sigaction SIGTSTP_action = {0};        // Initialize SIGINT_action struct to be empty
    SIGTSTP_action.sa_handler = backgroundSwitch; // Register background switch
    sigfillset(&SIGTSTP_action.sa_mask);          // Block all other catchable signals
    SIGTSTP_action.sa_flags = SA_RESTART;         // The easier solution is using SA_RESTART flag in the signal handler
    sigaction(SIGTSTP, &SIGTSTP_action, NULL);    // Inject the signal handler

    // Infinite run.
    while (1)
    {
        backflag = 0;                             // Reset the background flag to 0 for the new command
        cleanEntries(argVector, indexCounter);    // Clean up the vector for the next entry command if any exists.

        // Check for any ongoing background processes and report accordingly.
        checkComplete();

        // Entry Point
        printf(": ");
        fflush(stdout);

        // Entry parsing
        indexCounter = entryParser(commandInput, argVector, pid);

        // The zeroth index is the command, all else are optional arguments.
        // Parse the initial string for NULL (No entry is injected into the argument vector) or a comment starting with #
        if ((argVector[0] == NULL) || (strncmp(argVector[0], "#", 1) == 0))
        {
            continue; // These will not be parsed and simply continue.
        }

        // Check background or not, change the index
        backflag = backgroundCheck(argVector, indexCounter, backflag);

        // Change the index counter accordingly to accommodate for the removed & sign to invoke a background process.
        if (backflag)
        {
            indexCounter--;
        }

        // Background & in command is ignored - backflag will turn off.
        if (foregroundOnly)
        {
            backflag = 0;
        }

        // Exit command
        if (strcmp(argVector[0], "exit") == 0)
        {
            exitProcess(); // Exit ends the program - no need to actually "return" or set a continue.
        }

        // Change directory
        if (strcmp(argVector[0], "cd") == 0)
        {
            changeDir(argVector);
            continue; // Resume the program.
        }

        // Status - checks based on the value of the childStatus last ran in the background.
        if (strcmp(argVector[0], "status") == 0)
        {
            statusCheck(childStatus);
            continue; // Resume the program.
        }

        // Execute all other commands and return the processing status "returnedStatus" for use with the status command.
        int returnedStatus = execProcesses(argVector, pid, backflag, indexCounter);

        // If this was a foreground process, then inject the returnedStatus as the childStatus.
        // Also restore the signal accordingly to ignore interruptions.
        if (!backflag)
        {
            childStatus = returnedStatus;  // The injection...

            // Restore the ignore signal after execution (So no spamming)
            // Ignore Control C - reset back to this state if there is a change due to a foreground child.
            struct sigaction SIGINT_action = {0};    // Initialize SIGINT_action struct to be empty
            SIGINT_action.sa_handler = SIG_IGN;      // Register SIGIGN - signal ignore
            sigfillset(&SIGINT_action.sa_mask);      // Block all other catchable signals
            SIGINT_action.sa_flags = SA_RESTART;     // The easier solution is using SA_RESTART flag in the signal handler
            sigaction(SIGINT, &SIGINT_action, NULL); // Inject the signal handler
        }
    }
    return;
}
