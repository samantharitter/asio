//
// ssl/detail/engine.hpp
// ~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2015 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef ASIO_SSL_DETAIL_ENGINE_HPP
#define ASIO_SSL_DETAIL_ENGINE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "asio/detail/config.hpp"

#include "asio/detail/push_options.hpp"

#if defined(ASIO_USE_LAZYSSL)
// LazySSL
#include "asio/ssl/detail/lazyssl_engine.hpp"
#else
// default to OpenSSL
#include "asio/ssl/detail/openssl_engine.hpp"
#endif

#include "asio/detail/pop_options.hpp"

#endif // ASIO_SSL_DETAIL_ENGINE_HPP
