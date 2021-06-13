// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// A Status encapsulates the result of an operation.  It may indicate success,
// or it may indicate an error with an associated error message.
//
// Multiple threads can invoke const methods on a Status without
// external synchronization, but if any of the threads may call a
// non-const method, all threads accessing the same Status must use
// external synchronization.

#ifndef KUDU_UTIL_STATUS_H_
#define KUDU_UTIL_STATUS_H_

// NOTE: using stdint.h instead of cstdint and errno.h instead of cerrno because
// this file is supposed to be processed by a compiler lacking C++11 support.
#include <errno.h>
#include <stdint.h>

#include <cstddef>
#include <string>

#include "hs2client/status.h"

#if defined(__GNUC__)
#define PREDICT_FALSE(x) (__builtin_expect(x, 0))
#define PREDICT_TRUE(x) (__builtin_expect(!!(x), 1))
#else
#define PREDICT_FALSE(x) x
#define PREDICT_TRUE(x) x
#endif

/// @brief Return the given status if it is not @c OK.
#define RETURN_NOT_OK(s) do { \
    const ::hs2client::Status& _s = (s);             \
    if (PREDICT_FALSE(!_s.ok())) return _s;     \
  } while (0)

/// @brief Return the given status if it is not OK, but first clone it and
///   prepend the given message.
#define RETURN_NOT_OK_PREPEND(s, msg) do { \
    const ::hs2client::Status& _s = (s);                              \
    if (PREDICT_FALSE(!_s.ok())) return _s; \
  } while (0)

/// @brief Return @c to_return if @c to_call returns a bad status.
///   The substitution for 'to_return' may reference the variable
///   @c s for the bad status.
#define RETURN_NOT_OK_RET(to_call, to_return) do { \
    const ::hs2client::Status& s = (to_call);                \
    if (PREDICT_FALSE(!s.ok())) return (to_return);  \
  } while (0)

/// @brief Return the given status if it is not OK, evaluating `on_error` if so.
#define RETURN_NOT_OK_EVAL(s, on_error) do { \
    const ::hs2client::Status& _s = (s); \
    if (PREDICT_FALSE(!_s.ok())) { \
      (on_error); \
      return _s; \
    } \
  } while (0)

/// @brief Emit a warning if @c to_call returns a bad status.
#define WARN_NOT_OK(to_call, warning_prefix) do { \
    const ::hs2client::Status& _s = (to_call);              \
    if (PREDICT_FALSE(!_s.ok())) { \
      LOG(WARNING) << (warning_prefix) << ": " << _s.ToString();  \
    } \
  } while (0)

/// @brief Log the given status and return immediately.
#define LOG_AND_RETURN(level, status) do { \
    const ::hs2client::Status& _s = (status);        \
    LOG(level) << _s.ToString(); \
    return _s; \
  } while (0)

/// @brief If the given status is not OK, log it and 'msg' at 'level' and return the status.
#define RETURN_NOT_OK_LOG(s, level, msg) do { \
    const ::hs2client::Status& _s = (s);             \
    if (PREDICT_FALSE(!_s.ok())) { \
      LOG(level) << "Status: " << _s.ToString() << " " << (msg); \
      return _s;     \
    } \
  } while (0)

/// @brief If @c to_call returns a bad status, CHECK immediately with
///   a logged message of @c msg followed by the status.
#define CHECK_OK_PREPEND(to_call, msg) do { \
    const ::hs2client::Status& _s = (to_call);                   \
    CHECK(_s.ok()) << (msg) << ": " << _s.ToString();  \
  } while (0)

/// @brief If the status is bad, CHECK immediately, appending the status to the
///   logged message.
#define CHECK_OK(s) CHECK_OK_PREPEND(s, "Bad status")

/// @brief If @c to_call returns a bad status, DCHECK immediately with
///   a logged message of @c msg followed by the status.
#define DCHECK_OK_PREPEND(to_call, msg) do { \
    const ::hs2client::Status& _s = (to_call);                   \
    DCHECK(_s.ok()) << (msg) << ": " << _s.ToString();  \
  } while (0)

/// @brief If the status is bad, DCHECK immediately, appending the status to the
///   logged 'Bad status' message.
#define DCHECK_OK(s) DCHECK_OK_PREPEND(s, "Bad status")

/// @brief A macro to use at the main() function level if it's necessary to
///   return a non-zero status from the main() based on the non-OK status 's'
///   and extra message 'msg' prepended. The desired return code is passed as
///   'ret_code' parameter.
#define RETURN_MAIN_NOT_OK(to_call, msg, ret_code) do { \
    DCHECK_NE(0, (ret_code)) << "non-OK return code should not be 0"; \
    const ::hs2client::Status& _s = (to_call); \
    if (!_s.ok()) { \
      const ::hs2client::Status& _ss = _s.CloneAndPrepend((msg)); \
      LOG(ERROR) << _ss.ToString(); \
      return (ret_code); \
    } \
  } while (0)

/// @file status.h
///
/// This header is used in both the Kudu build as well as in builds of
/// applications that use the Kudu C++ client. In the latter we need to be
/// careful to "namespace" our macros, to avoid colliding or overriding with
/// similarly named macros belonging to the application.
///
/// KUDU_HEADERS_USE_SHORT_STATUS_MACROS handles this behavioral change. When
/// defined, we're building Kudu and:
/// @li Non-namespaced macros are allowed and mapped to the namespaced versions
///   defined above.
/// @li Namespaced versions of glog macros are mapped to the real glog macros
///   (otherwise the macros are defined in the C++ client stubs).

// These are standard glog macros.
#define KUDU_LOG              LOG
#define KUDU_CHECK            CHECK
#define KUDU_DCHECK           DCHECK

#endif  // KUDU_UTIL_STATUS_H_
