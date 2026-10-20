#ifndef NUCLEUS_LOG_H
#define NUCLEUS_LOG_H

void verbose    (int level, char const *fmt, ...);
void print_warn (char const *fmt, ...);
void print_err  (char const *fmt, ...);

/* Last print_err() text (thread-local), so embedders can surface the real
 * failure reason instead of only the generic wrapper message. */
void        nucleus_clear_last_error(void);
const char *nucleus_last_error(void);

#endif /* NUCLEUS_LOG_H */

