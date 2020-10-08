#pragma once

#include <grp.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>

#include <string>
#include <cstring>
#include <vector>

namespace obmc_priv {

#define OBMC_PRIV_PROTO_MAGIC 0xdeadbeaf

enum {
  TYPE_RESPONSE = 1,
  TYPE_PAM_AUTH = 10,
  TYPE_PAM_CHANGE
};

struct prsp_proto {
  uint32_t magic;
  uint32_t type;
  size_t len;
};


static bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16bit, hence explicitly avoid the 16bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}


static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}


static inline int maybe_setgroups(size_t size, const gid_t *list) {
#if 0
        int r;

        /* Check if setgroups is allowed before we try to drop all the auxiliary groups */
        if (size == 0) { /* Dropping all aux groups? */
                _cleanup_free_ char *setgroups_content = NULL;
                bool can_setgroups;

                r = read_one_line_file("/proc/self/setgroups", &setgroups_content);
                if (r == -ENOENT)
                        /* Old kernels don't have /proc/self/setgroups, so assume we can use setgroups */
                        can_setgroups = true;
                else if (r < 0)
                        return r;
                else
                        can_setgroups = streq(setgroups_content, "allow");

                if (!can_setgroups) {
                        log_debug("Skipping setgroups(), /proc/self/setgroups is set to 'deny'");
                        return 0;
                }
        }
#endif

        if (::setgroups(size, list) < 0)
                return -errno;

        return 0;
}


static inline int enforce_groups(gid_t gid, const gid_t *supplementary_gids, int ngids) {
        int r;

        /* Handle supplementary groups if it is not empty */
        if (ngids > 0) {
                r = maybe_setgroups(ngids, supplementary_gids);
                if (r < 0)
                        return r;
        }

        if (gid_is_valid(gid)) {
                /* Then set our gids */
                if (::setresgid(gid, gid, gid) < 0)
                        return -errno;
        }

        return 0;
}


static inline int enforce_user(uid_t uid) {
        if (!uid_is_valid(uid))
                return 0;

        /* Sets (but doesn't look up) the uid and make sure we keep the
         * capabilities while doing so. */

        if (true) { // context->capability_ambient_set != 0) {

                /* First step: If we need to keep capabilities but
                 * drop privileges we need to make sure we keep our
                 * caps, while we drop privileges. */
                if (uid != 0) {
                        int sb = ::prctl(PR_GET_SECUREBITS) | (1<<SECURE_KEEP_CAPS);

                        if (::prctl(PR_GET_SECUREBITS) != sb)
                                if (prctl(PR_SET_SECUREBITS, sb) < 0)
                                        return -errno;
                }
        }

        /* Second step: actually set the uids */
        if (::setresuid(uid, uid, uid) < 0)
                return -errno;

        /* At this point we should have all necessary capabilities but
           are otherwise a normal user. However, the caps might got
           corrupted due to the setresuid() so we need clean them up
           later. This is done outside of this call. */

        struct __user_cap_header_struct cap_hdr = {
          .version = _LINUX_CAPABILITY_VERSION_3,
          .pid = 0
        };
        struct __user_cap_data_struct cap_set = {};

        if (capget(&cap_hdr, NULL) < 0) {
            return -errno;
        }

        if (capget(&cap_hdr, &cap_set) < 0) {
            return -errno;
        }

        cap_set.effective = cap_set.permitted;
        if (capset(&cap_hdr, &cap_set) < 0) {
            return -errno;
        }

        return 0;
}


static inline int parse_uid(const char *str, uid_t *ret) {
    char *x = NULL;
    unsigned long l;
    struct passwd *p;

    p = ::getpwnam(str);
    if (p != NULL) {
        *ret = p->pw_uid;
        return 0;
    }

    l = ::strtoul(str, &x, 10);

    if (!x || x == str || *x != 0)
        return -EINVAL;

    if (!gid_is_valid(l))
        return -EINVAL;

    if (ret != NULL)
        *ret = (uid_t)l;

    return 0;
}


static inline int parse_gid(const char *str, gid_t *ret) {
    char *x = NULL;
    unsigned long l;
    struct group *g;

    g = ::getgrnam(str);
    if (g != NULL) {
        *ret = g->gr_gid;
        return 0;
    }

    l = ::strtoul(str, &x, 10);

    if (!x || x == str || *x != 0)
        return -EINVAL;

    if (!gid_is_valid(l))
        return -EINVAL;

    if (ret != NULL)
        *ret = (gid_t)l;

    return 0;
}


static inline int obmc_enforce_user(const char *user, const char *new_group, const char *supgrp) {
    int rc;
    gid_t gid;
    uid_t uid;
    std::vector<gid_t> gids;

    if (user == NULL)
        return -EINVAL;

    rc = parse_uid(user, &uid);
    if (rc < 0)
        return rc;

    if (new_group != NULL) {
        rc = parse_gid(new_group, &gid);
        if (rc < 0)
            return rc;
    } else {
        struct passwd *pw = ::getpwuid(uid);
        if (pw == NULL)
            return -errno;

        gid = pw->pw_gid;
    }

    if (supgrp != NULL) {
        gid_t v;
        size_t pos = 0;
        size_t oldpos = 0;
        std::string token;
        std::string s(supgrp);

        while ((pos = s.find(' ', oldpos)) != std::string::npos) {
            std::string token = s.substr(oldpos, pos);
            oldpos = pos + 1;

            if (token.empty())
                continue;

            rc = parse_gid(token.c_str(), &v);
            if (rc < 0)
                return rc;

            gids.push_back(v);
		}

        token = s.substr(oldpos);

        rc = parse_gid(token.c_str(), &v);
        if (rc < 0)
            return rc;

        gids.push_back(v);
    }

    rc = enforce_groups(gid, gids.data(), gids.size());
    if (rc < 0)
        return rc;

    return enforce_user(uid);
}

static void proc_exit(int signum)
{
    int wstat = 0;
    pid_t pid;

    for (;;) {
      pid = ::wait3(&wstat, WNOHANG, NULL);
      if (pid == 0)
        return;
      else if (pid == -1)
        break;
    }
    ::exit(WEXITSTATUS(wstat));
}

static inline int daemonize(int *socket_fd)
{
  int socket_vector[2];

  if (geteuid() != 0) {
    *socket_fd = -1;
    return 0;
  }

  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector) != 0) {
    return -errno;
  }

  ::signal(SIGCHLD, proc_exit);

  pid_t child_pid = ::fork();

  if (child_pid < 0) {
    return -errno;
  } else if (child_pid == 0) {
    if (getenv("LISTEN_PID") != NULL) {
      char *listen_pid;
      asprintf(&listen_pid, "LISTEN_PID=%d", getpid());
      if (putenv(listen_pid) < 0) {
        free(listen_pid);
      }
    }

    ::close(socket_vector[0]);

    *socket_fd = socket_vector[1];
    return obmc_enforce_user(getenv("USER"),
                             getenv("SYSTEMD_RUN_AS_GROUP"),
                             getenv("SYSTEMD_RUN_WITH_GROUPS"));
  } else {
    ::close(socket_vector[1]);

    *socket_fd = socket_vector[0];
  }

  return child_pid;
}

static int read_data(int fd, void *buf, size_t len)
{
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = len
  };

  int rc = 0;
  for (;;) {
    rc = readv(fd, &iov, 1);
    if (rc > 0) {
      break;
    } else if (rc == 0) {
      return -EBADF;
    } else if (rc == -1) {
      switch (errno) {
        case EINTR:
        case ERESTART:
          continue;

        case ECONNRESET:
        case ENOTCONN:
        case ESHUTDOWN:
        case ECONNABORTED:
        case EPIPE:
        case EBADF:
        case ECONNREFUSED:
        case ETIMEDOUT:
          return -errno;
      }
    }
  }

  return rc;
}

static int write_data(int fd, uint32_t type, void *buf, size_t len)
{
  if (buf == NULL) {
    return -EINVAL;
  }

  struct obmc_priv::prsp_proto hdr = {
    .magic = OBMC_PRIV_PROTO_MAGIC,
    .type = type,
    .len = len
  };

  struct iovec iov[] = {
    { .iov_base = &hdr,
      .iov_len = sizeof(hdr) },
    { .iov_base = buf,
      .iov_len = len }
  };
  
  return ::writev(fd, iov, 2);
}

} // namespace priv
