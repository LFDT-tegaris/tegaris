/* Local acceptance fault at the real filesystem commit boundary. This shared
 * library is mounted only by the local runtime harness; no service links it.
 * It never reads or changes a decision. The driver must authenticate RESERVED
 * after observing the marker, then kill only its owned target and verify recovery.
 */
/* Only POSIX/default interfaces are needed. _GNU_SOURCE selects newer C23
 * scanf symbols on recent hosts that the pinned Bookworm runtime lacks. */
#define _DEFAULT_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

static int (*real_fsync)(int);
static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static ssize_t (*real_write)(int, const void *, size_t);
static pthread_once_t write_initialized = PTHREAD_ONCE_INIT;

static void resolve_fsync(void) {
  *(void **)(&real_fsync) = dlsym(RTLD_NEXT, "fsync");
  if (!real_fsync) _exit(190);
}

static void resolve_write(void) {
  *(void **)(&real_write) = dlsym(RTLD_NEXT, "write");
  if (!real_write) _exit(190);
}

/* Observe only a genuine failed write. No syscall result, errno, journal byte,
 * capacity setting or dispatch decision is manufactured by this observer.
 * The arm and bounded marker live outside the full filesystem. */
static void observe_enospc(int fd) {
  const char *directory = getenv("OPENPC_RPC_JOURNAL_FAULT_DIRECTORY");
  const char *control = getenv("OPENPC_RPC_JOURNAL_ENOSPC_CONTROL_DIRECTORY");
  if (!directory || !control || directory[0] != '/' || control[0] != '/' ||
      geteuid() != 65532 || getegid() != 65532) return;

  char canonical[PATH_MAX], descriptor[64], actual[PATH_MAX], expected_path[PATH_MAX];
  if (!realpath(directory, canonical) || strcmp(canonical, directory) != 0 ||
      !realpath(control, canonical) || strcmp(canonical, control) != 0) return;
  if (snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd) >= (int)sizeof descriptor ||
      snprintf(expected_path, sizeof expected_path, "%s/sealed-decisions.next", directory) >= (int)sizeof expected_path)
    return;
  ssize_t length = readlink(descriptor, actual, sizeof actual - 1);
  if (length < 0 || length >= (ssize_t)sizeof actual - 1) return;
  actual[length] = '\0';
  if (strcmp(actual, expected_path) != 0) return;

  int source = -1, parent = -1, arm = -1, marker = -1;
  struct stat root, outside, staged, named, armed, current, mount_ns, pid_ns;
  struct statfs filesystem;
  source = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  parent = open(control, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (source < 0 || parent < 0 || fstat(source, &root) != 0 || fstat(parent, &outside) != 0 ||
      root.st_uid != 65532 || root.st_gid != 65532 || (root.st_mode & 0777) != 0700 ||
      outside.st_uid != 65532 || outside.st_gid != 65532 || (outside.st_mode & 0777) != 0700 ||
      outside.st_dev == root.st_dev || fstatfs(source, &filesystem) != 0 ||
      filesystem.f_type != 0x01021994 ||
      (unsigned long long)filesystem.f_blocks * (unsigned long long)filesystem.f_bsize != 67108864ULL ||
      filesystem.f_bavail != 0 || filesystem.f_ffree == 0 ||
      fstat(fd, &staged) != 0 || !S_ISREG(staged.st_mode) || staged.st_nlink != 1 ||
      staged.st_uid != 65532 || staged.st_dev != root.st_dev || staged.st_size <= 0 ||
      fstatat(source, "sealed-decisions.next", &named, AT_SYMLINK_NOFOLLOW) != 0 ||
      named.st_dev != staged.st_dev || named.st_ino != staged.st_ino ||
      stat("/proc/self/ns/mnt", &mount_ns) != 0 || stat("/proc/self/ns/pid", &pid_ns) != 0)
    goto done;

  arm = openat(parent, "enospc.arm", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (arm < 0 || fstat(arm, &armed) != 0 || !S_ISREG(armed.st_mode) || armed.st_nlink != 1 ||
      armed.st_uid != 65532 || armed.st_gid != 65532 || (armed.st_mode & 0777) != 0600 || armed.st_size <= 0 || armed.st_size >= 256)
    goto done;
  char intent[256], token[33];
  long pid;
  unsigned long long expected_mount, expected_pid_ns, device, inode;
  int parsed = 0;
  length = read(arm, intent, sizeof intent - 1);
  if (length != armed.st_size) goto done;
  intent[length] = '\0';
  if (sscanf(intent, "OPENPC_RPC_ENOSPC_ARM_V1 %32[0-9a-f] %ld %llu %llu %llu %llu%n",
             token, &pid, &expected_mount, &expected_pid_ns, &device, &inode, &parsed) != 6 ||
      strlen(token) != 32 || parsed != length - 1 || intent[parsed] != '\n' ||
      pid != (long)getpid() || expected_mount != (unsigned long long)mount_ns.st_ino ||
      expected_pid_ns != (unsigned long long)pid_ns.st_ino ||
      device != (unsigned long long)root.st_dev || inode != (unsigned long long)root.st_ino)
    goto done;
  /* Match the exact arm inode before consuming it. Only one observer wins. */
  if (fstatat(parent, "enospc.arm", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
      current.st_dev != armed.st_dev || current.st_ino != armed.st_ino ||
      unlinkat(parent, "enospc.arm", 0) != 0) goto done;
  marker = openat(parent, "enospc.observed", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (marker < 0) goto done;
  char observation[256];
  int size = snprintf(observation, sizeof observation,
      "OPENPC_RPC_ENOSPC_V1 %s %ld %llu %llu %llu %llu %llu %llu ENOSPC\n",
      token, pid, expected_mount, expected_pid_ns, device, inode,
      (unsigned long long)staged.st_ino, (unsigned long long)staged.st_size);
  if (size <= 0 || size >= (int)sizeof observation) goto done;
  for (ssize_t offset = 0; offset < size;) {
    ssize_t count = real_write(marker, observation + offset, (size_t)(size - offset));
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) goto done;
    offset += count;
  }
  pthread_once(&initialized, resolve_fsync);
  if (real_fsync(marker) != 0) goto done;
  (void)real_fsync(parent);
done:
  if (marker >= 0) close(marker);
  if (arm >= 0) close(arm);
  if (parent >= 0) close(parent);
  if (source >= 0) close(source);
}

ssize_t write(int fd, const void *buffer, size_t count) {
  int caller_errno = errno;
  pthread_once(&write_initialized, resolve_write);
  errno = caller_errno;
  ssize_t result = real_write(fd, buffer, count);
  int saved_errno = errno;
  if (result < 0 && saved_errno == ENOSPC && count > 0) observe_enospc(fd);
  errno = saved_errno;
  return result;
}

int fsync(int fd) {
  pthread_once(&initialized, resolve_fsync);
  int result = real_fsync(fd);
  int saved_errno = errno;
  const char *directory = getenv("OPENPC_RPC_JOURNAL_FAULT_DIRECTORY");
  struct stat metadata;
  if (result != 0 || !directory || directory[0] != '/' ||
      fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) goto done;

  char descriptor[64], path[PATH_MAX], arm[PATH_MAX], reached[PATH_MAX];
  if (snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd) >= (int)sizeof descriptor)
    goto done;
  ssize_t length = readlink(descriptor, path, sizeof path - 1);
  if (length < 0 || length >= (ssize_t)sizeof path - 1) goto done;
  path[length] = '\0';
  if (strcmp(path, directory) != 0) goto done;
  if (snprintf(arm, sizeof arm, "%s/acceptance-pause.arm", directory) >= (int)sizeof arm ||
      snprintf(reached, sizeof reached, "%s/acceptance-pause.reached", directory) >= (int)sizeof reached)
    goto done;

  int armed = open(arm, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (armed < 0) goto done;
  char intent[64], expected[64];
  length = read(armed, intent, sizeof intent);
  int regular = fstat(armed, &metadata) == 0 && S_ISREG(metadata.st_mode);
  close(armed);
  int expected_length = snprintf(expected, sizeof expected, "pause-after-fsync:%ld\n", (long)getpid());
  if (!regular || length != expected_length || memcmp(intent, expected, length) != 0)
    goto done;
  /* Exactly one thread may consume the arm file. A stale marker fails closed. */
  if (unlink(arm) != 0) goto done;
  int marker = open(reached, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (marker < 0 || write(marker, expected, expected_length) != expected_length ||
      real_fsync(marker) != 0 || close(marker) != 0) _exit(190);
  /* A PID-namespace init can ignore self-issued SIGSTOP. Block this exact
   * fsync caller instead; signals can never resume its dispatch. The owning
   * driver reads the durable state independently and kills this process. */
  for (;;) pause();
done:
  errno = saved_errno;
  return result;
}
