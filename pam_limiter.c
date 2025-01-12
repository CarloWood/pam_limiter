// PAM module to limit the number of login attempts from a given IP address.

// Compile with: gcc -fPIC -shared -o pam_limiter.so pam_limiter.c
// Install with: sudo cp pam_limiter.so /lib/x86_64-linux-gnu/security/

// This is needed to get the strptime function.
#define _XOPEN_SOURCE

// This is needed to get the vsyslog function.
#define _DEFAULT_SOURCE

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <sys/wait.h>

#define MAX_USERNAME 32
#define MAX_ATTEMPTS 1000               // Maximum number of attempts that will be stored in the file.

#define USERNAME_FORMAT_STRING "%31s"   // Must match MAX_USERNAME-1.
#define VAR_RUN_DIRECTORY "/var/run/pam_limiter"
#define MAX_ATTEMPTS_FILENAME_LENGTH 37 // strlen(VAR_RUN_DIRECTORY) + strlen("123.123.123.123") + 1.

struct LoginAttempt
{
  time_t timestamp;
  char username[MAX_USERNAME];
};

typedef struct LoginAttempt LoginAttempt;

struct UserHost
{
  char const* user;
  char const* rhost;
};

typedef struct UserHost UserHost;

struct Config
{
  int max_failed_attempts;      // Number of failed attempts before banning.
  int fail_interval;            // Time interval in seconds to consider for failed attempts.
  int unlock_time;              // Time in seconds to keep the IP address banned.
};

typedef struct Config Config;

void vlog_error(char const* format, va_list args)
{
  openlog("pam_limiter", LOG_PID, LOG_AUTH);
  vsyslog(LOG_ERR, format, args);
  closelog();
}

void log_error(char const* format, ...)
{
  va_list args;
  va_start(args, format);
  vlog_error(format, args);
  va_end(args);
}

int fatal_error(char const* format, ...)
{
  va_list args;
  va_start(args, format);
  vlog_error(format, args);
  va_end(args);

  return -1;
}

void vlog_attempt_plus(char const* message, UserHost* user_host, char const* format, va_list args)
{
  openlog("pam_limiter", LOG_PID, LOG_AUTH);

  // First format the base message, if any.
  char base_msg[256];
  if (user_host)
    snprintf(base_msg, sizeof(base_msg), "%s from %s for user %s", message, user_host->rhost, user_host->user);
  else if (message)
    snprintf(base_msg, sizeof(base_msg), "%s", message);
  else
    base_msg[0] = '\0';

  if (format)
  {
    // Then append any additional info using varargs.
    char extra_info[256];
    vsnprintf(extra_info, sizeof(extra_info), format, args);
    syslog(LOG_INFO, "%s %s.", base_msg, extra_info);
  }
  else
    syslog(LOG_INFO, "%s.", base_msg);

  closelog();
}

void log_attempt_plus(char const* message, UserHost* user_host, char const* format, ...)
{
  va_list args;
  va_start(args, format);
  vlog_attempt_plus(message, user_host, format, args);
  va_end(args);
}

void log_attempt(char const* message, UserHost* user_host)
{
  log_attempt_plus(message, user_host, NULL);
}

void log_info(char const* format, ...)
{
  va_list args;
  va_start(args, format);
  vlog_attempt_plus(NULL, NULL, format, args);
  va_end(args);
}

// Returns 0 on success, otherwise the value returned by snprintf (-1 or something greater than or equal to size).
int get_filename(char const* ip_addr, char* filename, size_t size)
{
  int len = snprintf(filename, size, VAR_RUN_DIRECTORY "/%s", ip_addr);
  if (len < 0 || len == size)   // Failure or truncated.
    return len;
  return 0;
}

// Open and lock a file for the given IP address.
int open_and_lock_file(char const* ip_addr)
{
  // First ensure the directory exists.
  if (mkdir(VAR_RUN_DIRECTORY, 0755) == -1 && errno != EEXIST)
    return fatal_error("Failed to create directory \"" VAR_RUN_DIRECTORY "\": %s", strerror(errno));

  // Construct the filename.
  char filename[MAX_ATTEMPTS_FILENAME_LENGTH];
  int len = get_filename(ip_addr, filename, sizeof(filename));
  if (len != 0)
    return fatal_error("Failed to construct filename: len = %d", len);

  // Open file for read+write, create if doesn't exist.
  int fd = open(filename, O_RDWR|O_CREAT|O_APPEND, 0644);
  if (fd == -1)
    return fatal_error("Failed to open file \"%s\": %s", filename, strerror(errno));

  // Get an exclusive lock - will wait if already locked.
  if (flock(fd, LOCK_EX) == -1)
  {
    close(fd);
    return fatal_error("Failed to lock file \"%s\": %s", filename, strerror(errno));
  }

  return fd;
}

// Close and unlock when done.
void close_and_unlock(int fd)
{
  if (fd != -1)
  {
    flock(fd, LOCK_UN);
    close(fd);
  }
}

// Write new authentication attempt to the file.
int write_attempt(int fd, char const* username, time_t now)
{
  struct tm* tm = localtime(&now);
  char timestamp[32];

  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

  char line[256];
  snprintf(line, sizeof(line), "%s %s\n", timestamp, username);

  return write(fd, line, strlen(line));
}

int fatal_error_fd(int fd, char const* format, ...)
{
  openlog("pam_limiter", LOG_PID, LOG_AUTH);

  va_list args;
  va_start(args, format);
  vsyslog(LOG_ERR, format, args);
  va_end(args);

  closelog();
  close_and_unlock(fd);
  return -1;
}

// Read the history of login attempts for the given IP address.
// Returns the number of attempts in the last hour, or -1 on error.
int append_history(UserHost const* user_host, Config const* config)
{
  // Open the file.
  int fd = open_and_lock_file(user_host->rhost);
  if (fd == -1)
    return -1;

  // Write the new attempt.
  time_t now = time(NULL);
  if (write_attempt(fd, user_host->user, now) == -1)
    return fatal_error_fd(fd, "Failed attempt write: %s", strerror(errno));

  // Try to read existing contents.
  FILE* f = fdopen(fd, "r");
  if (!f)
    return fatal_error_fd(fd, "Failed to fdopen: %s", strerror(errno));

  // Reset to beginning of file.
  fseek(f, 0, SEEK_SET);

  char line[256];
  int count = 0;

  // Each line format: "YYYY-MM-DD HH:MM:SS username"
  while (count < MAX_ATTEMPTS && fgets(line, sizeof(line), f))
  {
    struct tm tm;
    char username[MAX_USERNAME];

    if (strptime(line, "%Y-%m-%d %H:%M:%S ", &tm) &&
        sscanf(line + 20, USERNAME_FORMAT_STRING, username) == 1)
    {
      username[MAX_USERNAME - 1] = '\0';
      time_t timestamp = mktime(&tm);
      if (now - timestamp < config->fail_interval)
      {
        ++count;
      }
    }
    else
    {
      openlog("pam_limiter", LOG_PID, LOG_AUTH);
      syslog(LOG_INFO, "Failed to parse line");
      closelog();
    }
  }

  // We need to keep the fd but can close the FILE*.
  fflush(f);
  fclose(f);

  return count;
}

UserHost get_user_host(pam_handle_t* pamh)
{
  UserHost user_host;

  // Get username.
  if (pam_get_user(pamh, &user_host.user, NULL) != PAM_SUCCESS)
    user_host.user = "unknown";

  // Get remote host.
  if (pam_get_item(pamh, PAM_RHOST, (void const**)&user_host.rhost) != PAM_SUCCESS || !user_host.rhost)
    user_host.rhost = "unknown";

  return user_host;
}

// Run external command.
int run_trigger(char const* cmd, char const* ip_addr)
{
  pid_t pid = fork();
  if (pid == (pid_t)-1)
    return fatal_error("Can not fork, failed to run trigger");

  if (!pid)
  {
    char* argv[4];

    char const* trigger_cmd = "/usr/local/sbin/pam_limiter_trigger";
    argv[0] = (char*)trigger_cmd;
    argv[1] = (char*)cmd;
    argv[2] = (char*)ip_addr;
    argv[3] = NULL;

    execvp(argv[0], argv);

    log_error("Failed to execute command '%s %s %s'", trigger_cmd, cmd, ip_addr);
    exit(-1);
  }
  else
  {
    pid_t err;
    int status;

    while ((err = waitpid(pid, &status, 0)) > 0)
      ;

    if (WEXITSTATUS(status) != 0)
      return -1;
  }

  return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, char const** argv)
{
  // Get the user and remote host.
  UserHost user_host = get_user_host(pamh);

  // Get the configuration.
  Config config = { .max_failed_attempts = 5, .fail_interval = 3600, .unlock_time = 604800 };       // Default values.

  // Append the history.
  int num_attempts_in_the_last_hour = append_history(&user_host, &config);

  // Just log the attempt - we're returning PAM_IGNORE to let the next module decide if the user is allowed to log in.
  log_attempt_plus("Auth attempt", &user_host, "(attempt %d)", num_attempts_in_the_last_hour);

  // If the number of attempts in the last hour, including this attempt, exceeds config.max_failed_attempts, ban the IP address.
  if (num_attempts_in_the_last_hour > config.max_failed_attempts)
  {
    // Block the IP address.
    log_info("Blocking IP address %s.", user_host.rhost);
    run_trigger("add", user_host.rhost);

    // Immediately terminate because no further communication is even possible.
    // This is why /etc/pam.d/sshd must contain "auth requisite pam_limiter.so" at the beginning.
    return PAM_MAXTRIES;
  }

  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  // Get the user and remote host.
  UserHost user_host = get_user_host(pamh);

  // If we reach this function, authentication was successful.
  log_attempt("Successful authentication", &user_host);

  // Get the attempts filename.
  char filename[MAX_ATTEMPTS_FILENAME_LENGTH];
  int len = get_filename(user_host.rhost, filename, sizeof(filename));
  if (len != 0)
  {
    (void)fatal_error("Could not delete attempts file for %s: failed to construct filename: len = %d", user_host.rhost, len);
    return PAM_IGNORE;
  }

  // Open and lock the file.
  int fd = open_and_lock_file(user_host.rhost);

  // Delete the file because the user has successfully authenticated.
  if (unlink(filename) == -1)
    log_error("Failed to delete attempts file \"%s\" (%s)", filename, strerror(errno));

  // Close and unlock the file.
  if (fd != -1)
    close_and_unlock(fd);

  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, char const** argv)
{
  return PAM_SUCCESS;
}
