/*    Copyright (c) 2021, Big Data Technology. All Rights Reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <erl_nif.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define ERRBUF_SIZE 8192

typedef struct {
  pthread_t tid;
  ErlNifEnv *env;
  ErlNifPid owner;
  ErlNifCond *cond;
  ErlNifMutex *mtx;
  char *error_reason;
  char *watch_dir;
  struct pollfd fds[1];
} state_t;

ERL_NIF_TERM atom_error;
ERL_NIF_TERM atom_ok;
ERL_NIF_TERM atom_undefined;
ERL_NIF_TERM atom_file;
ERL_NIF_TERM atom_close_write;
ERL_NIF_TERM atom_moved_to;
ERL_NIF_TERM atom_enotify_event;
ERL_NIF_TERM atom_enotify_critical;
ERL_NIF_TERM atom_enotify_debug;
ERL_NIF_TERM atom_enotify_error;
ERL_NIF_TERM atom_enotify_warning;

static ErlNifResourceType *state_r = NULL;

static void signal_handler(int signal) {
  /* We do nothing here */
  return;
}

static void set_signal_handler() {
  sigset_t set;
  struct sigaction act = {0};

  act.sa_handler = signal_handler;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  act.sa_mask = set;
  sigaction(SIGUSR1, &act, 0);
}

static void unset_signal_handler() {
  /* TODO: return SIGUSR1 control back to Erlang VM */
  return;
}

static ERL_NIF_TERM make_strerror(ErlNifEnv *env, const char *reason) {
  return enif_make_tuple2(env, atom_error,
                          enif_make_string(env, reason, ERL_NIF_LATIN1));
}

static void send_event(state_t *state, const struct inotify_event *event) {
  int ret;
  ERL_NIF_TERM ev_mask;

  switch (event->mask) {
  case IN_CLOSE_WRITE:
    ev_mask = atom_close_write;
    break;
  case IN_MOVED_TO:
    ev_mask = atom_moved_to;
    break;
  default:
    ev_mask = atom_undefined;
  }

  ret = enif_send(NULL, &state->owner, state->env,
                  enif_make_tuple3(
                      state->env, atom_enotify_event,
                      enif_make_resource(state->env, state),
                      enif_make_tuple3(state->env, ev_mask, atom_file,
                                       enif_make_string(state->env, event->name,
                                                        ERL_NIF_LATIN1))));
  if (ret)
    enif_clear_env(state->env);
}

static void notify_owner(state_t *state, ERL_NIF_TERM tag, const char *name) {
  int ret;

  ret = enif_send(
      NULL, &state->owner, state->env,
      enif_make_tuple3(state->env, tag, enif_make_resource(state->env, state),
                       enif_make_string(state->env, name, ERL_NIF_LATIN1)));
  if (ret)
    enif_clear_env(state->env);
}

static int inotify_handle_events(state_t *state) {
  char buf[4096];
  const struct inotify_event *event;
  ssize_t len;
  char *ptr;

  while (1) {
    len = read(state->fds[0].fd, buf, sizeof buf);
    if (len == -1 && errno != EAGAIN) {
      snprintf(state->error_reason, ERRBUF_SIZE,
               "Failed to read from inotify descriptor: %s", strerror(errno));
      return -1;
    }
    if (len <= 0)
      break;

    for (ptr = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {
      event = (const struct inotify_event *)ptr;
      if (event->mask & IN_Q_OVERFLOW) {
        strncpy(state->error_reason, "Inotify event queue is overfilled",
                ERRBUF_SIZE);
        return -1;
      }
      if (event->mask & IN_IGNORED) {
        snprintf(state->error_reason, ERRBUF_SIZE,
                 "The watching directory %s was removed", state->watch_dir);
        return -1;
      }
      if (event->mask & IN_ISDIR)
        continue;
      if (event->mask & IN_CLOSE_WRITE || event->mask & IN_MOVED_TO) {
        if (event->len)
          send_event(state, event);
      }
    }
  }

  return 0;
}

void inotify_poll(state_t *state) {
  int poll_num;
  short revents;

  state->fds[0].events = POLLIN;

  while (1) {
    poll_num = poll(state->fds, 1, -1);
    if (poll_num == -1) {
      if (errno == EINTR)
        continue;
      snprintf(state->error_reason, ERRBUF_SIZE,
               "Failed to poll inotify descriptor: %s", strerror(errno));
      break;
    } else if (poll_num > 0) {
      revents = state->fds[0].revents;
      if (revents & POLLIN) {
        if (inotify_handle_events(state))
          break;
      } else if (revents & POLLERR || revents & POLLHUP || revents & POLLNVAL) {
        strncpy(state->error_reason,
                "Inotify descriptor was closed unexpectedly", ERRBUF_SIZE);
        break;
      }
    }
  }
}

void inotify_close(state_t *state) {
  if (state->fds[0].fd > 0) {
    close(state->fds[0].fd);
    state->fds[0].fd = 0;
  }
}

static void *inotify_loop(void *args) {
  int wd;
  state_t *state = (state_t *)args;
  enif_mutex_lock(state->mtx);
  set_signal_handler();
  state->tid = pthread_self();
  state->env = enif_alloc_env();

  if (!state->env) {
    snprintf(state->error_reason, ERRBUF_SIZE, "%s", strerror(ENOMEM));
    goto cleanup;
  }

  state->fds[0].fd = inotify_init1(IN_NONBLOCK);

  if (state->fds[0].fd == -1) {
    snprintf(state->error_reason, ERRBUF_SIZE,
             "Failed to initialize inotify: %s", strerror(errno));
    goto cleanup;
  }

  wd = inotify_add_watch(state->fds[0].fd, state->watch_dir,
                         IN_CLOSE_WRITE | IN_MOVED_TO);
  if (wd == -1) {
    snprintf(state->error_reason, ERRBUF_SIZE,
             "Failed to watch directory %s: %s", state->watch_dir,
             strerror(errno));
    goto cleanup;
  }

  enif_cond_signal(state->cond);
  enif_mutex_unlock(state->mtx);

  inotify_poll(state);

  enif_mutex_lock(state->mtx);
  if (state->fds[0].fd)
    notify_owner(state, atom_enotify_critical, state->error_reason);

cleanup:
  if (state->env) {
    enif_free_env(state->env);
    state->env = NULL;
  }
  inotify_close(state);
  unset_signal_handler();
  enif_cond_signal(state->cond);
  enif_mutex_unlock(state->mtx);
  return NULL;
}

static void destroy_state(ErlNifEnv *env, void *data) {
  state_t *state = (state_t *)data;
  if (state->mtx && state->cond) {
    enif_mutex_lock(state->mtx);
    if (state->watch_dir && state->fds[0].fd > 0) {
      inotify_close(state);
      pthread_kill(state->tid, SIGUSR1);
      enif_mutex_unlock(state->mtx);
      pthread_join(state->tid, NULL);
    } else
      enif_mutex_unlock(state->mtx);
  }
  if (state->mtx)
    enif_mutex_destroy(state->mtx);
  if (state->cond)
    enif_cond_destroy(state->cond);
  enif_free(state->error_reason);
  enif_free(state->watch_dir);
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info) {
  ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
  state_r =
      enif_open_resource_type(env, NULL, "state_r", destroy_state, flags, NULL);

  atom_error = enif_make_atom(env, "error");
  atom_ok = enif_make_atom(env, "ok");
  atom_undefined = enif_make_atom(env, "undefined");
  atom_file = enif_make_atom(env, "file");
  atom_close_write = enif_make_atom(env, "close_write");
  atom_moved_to = enif_make_atom(env, "moved_to");
  atom_enotify_event = enif_make_atom(env, "enotify_event");
  atom_enotify_critical = enif_make_atom(env, "enotify_critical");
  atom_enotify_debug = enif_make_atom(env, "enotify_debug");
  atom_enotify_error = enif_make_atom(env, "enotify_error");
  atom_enotify_warning = enif_make_atom(env, "enotify_warning");

  return 0;
}

static ERL_NIF_TERM rm_watch_nif(ErlNifEnv *env, int argc,
                                 const ERL_NIF_TERM argv[]) {
  state_t *state;

  if (argc != 1)
    return enif_make_badarg(env);

  if (!enif_get_resource(env, argv[0], state_r, (void *)&state))
    return atom_ok;

  destroy_state(env, state);
  memset(state, 0, sizeof(state_t));

  return atom_ok;
}

static ERL_NIF_TERM watch_dir_nif(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]) {
  ErlNifTid tid;
  ErlNifBinary watch_dir;
  ERL_NIF_TERM resource;
  int ret;

  state_t *state = enif_alloc_resource(state_r, sizeof(state_t));

  if (!state)
    return make_strerror(env, strerror(ENOMEM));

  memset(state, 0, sizeof(state_t));
  resource = enif_make_resource(env, state);
  enif_release_resource(state);

  if (argc != 1)
    return enif_make_badarg(env);

  if (!enif_inspect_binary(env, argv[0], &watch_dir))
    return enif_make_badarg(env);

  if (!enif_self(env, &state->owner))
    return enif_make_badarg(env);

  state->mtx = enif_mutex_create("enotify_loop_mtx");
  state->cond = enif_cond_create("enotify_loop_cond");
  state->error_reason = enif_alloc(ERRBUF_SIZE + 1);
  state->watch_dir = enif_alloc(watch_dir.size + 1);

  if (!(state->mtx && state->cond && state->error_reason && state->watch_dir))
    return make_strerror(env, strerror(ENOMEM));

  memcpy(state->watch_dir, watch_dir.data, watch_dir.size);
  state->watch_dir[watch_dir.size] = 0;

  enif_mutex_lock(state->mtx);
  ret = enif_thread_create("enotify_loop", &tid, inotify_loop, state, NULL);
  if (ret) {
    enif_mutex_unlock(state->mtx);
    return make_strerror(env, strerror(errno));
  } else {
    enif_cond_wait(state->cond, state->mtx);
    enif_mutex_unlock(state->mtx);
    if (!strlen(state->error_reason)) {
      return enif_make_tuple2(env, atom_ok, resource);
    } else
      return make_strerror(env, state->error_reason);
  }
}

static ErlNifFunc nif_funcs[] = {{"watch_dir_nif", 1, watch_dir_nif, 0},
                                 {"rm_watch_nif", 1, rm_watch_nif, 0}};

ERL_NIF_INIT(enotify, nif_funcs, load, NULL, NULL, NULL)
