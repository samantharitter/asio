// proof of concept.

#ifndef ASIO_SSL_DETAIL_LAZYSSL_ENGINE_HPP
#define ASIO_SSL_DETAIL_LAZYSSL_ENTINE_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "asio/buffer.hpp"
#include "asio/detail/static_mutex.hpp"
#include "asio/ssl/detail/openssl_types.hpp"
#include "asio/ssl/detail/verify_callback.hpp"
#include "asio/ssl/stream_base.hpp"
#include "asio/ssl/verify_mode.hpp"

namespace asio {
namespace ssl {
namespace detail {

// Placeholders
namespace {
const auto kErrorCode = asio::error::operation_not_supported;
const auto kEmptyString = "";
}

class engine {
public:
  enum want {
    // Returned by functions to indicate that the engine wants input. The input
    // buffer should be updated to point to the data. The engine then needs to
    // be called again to retry the operation.
    want_input_and_retry = -2,

    // Returned by functions to indicate that the engine wants to write output.
    // The output buffer points to the data to be written. The engine then
    // needs to be called again to retry the operation.
    want_output_and_retry = -1,

    // Returned by functions to indicate that the engine doesn't need input or
    // output.
    want_nothing = 0,

    // Returned by functions to indicate that the engine wants to write output.
    // The output buffer points to the data to be written. After that the
    // operation is complete, and the engine does not need to be called again.
    want_output = 1
  };

  // Construct a new engine for the specified context.
  ASIO_DECL explicit engine(SSL_CTX *context) {}

  // Destructor.
  ASIO_DECL ~engine() {}

  // Get the underlying implementation in the native type.
  ASIO_DECL SSL *native_handle() {}

  // Set the peer verification mode.
  ASIO_DECL asio::error_code set_verify_mode(verify_mode v,
                                             asio::error_code &ec) {
    std::cout << "set_verify_mode(): but I don't feel like it" << std::endl;
    return asio::error_code();
  }

  // Set the peer verification depth.
  ASIO_DECL asio::error_code set_verify_depth(int depth, asio::error_code &ec) {
    std::cout << "set_verify_depth(): eh, nah." << std::endl;
    return asio::error_code();
  }

  // Set a peer certificate verification callback.
  ASIO_DECL asio::error_code set_verify_callback(verify_callback_base *callback,
                                                 asio::error_code &ec) {
    std::cout << "set_verify_callback(): do it yourself" << std::endl;
    return asio::error_code();
  }

  // Perform an SSL handshake using either SSL_connect (client-side) or
  // SSL_accept (server-side).
  ASIO_DECL want
  handshake(stream_base::handshake_type type, asio::error_code &ec) {
    std::cout << "handshake(): nah" << std::endl;
    return want_nothing;
  }

  // Perform a graceful shutdown of the SSL session.
  ASIO_DECL want shutdown(asio::error_code &ec) {
    std::cout << "shutdown(): finally, a nap" << std::endl;
    return want_nothing;
  }

  // Write bytes to the SSL session.
  ASIO_DECL want write(const asio::const_buffer &data, asio::error_code &ec,
                       std::size_t &bytes_transferred) {
    std::cout << "write(): no." << std::endl;
    bytes_transferred = 0;
    ec = asio::error_code();
  }

  // Read bytes from the SSL session.
  ASIO_DECL want read(const asio::mutable_buffer &data, asio::error_code &ec,
                      std::size_t &bytes_transferred) {
    std::cout << "read(): don't think so" << std::endl;
    bytes_transferred = 0;
    ec = asio::error::operation_not_supported;
  }

  // Get output data to be written to the transport.
  ASIO_DECL asio::mutable_buffers_1
  get_output(const asio::mutable_buffer &data) {
    std::cout << "get_output(): but I just sat down" << std::endl;
    return asio::mutable_buffers_1(asio::mutable_buffer());
  }

  // Put input data that was read from the transport.
  ASIO_DECL asio::const_buffer put_input(const asio::const_buffer &data) {
    std::cout << "put_input(): but my back hurts" << std::endl;
    return asio::mutable_buffer();
  }

  // Map an error::eof code returned by the underlying transport according to
  // the type and state of the SSL session. Returns a const reference to the
  // error code object, suitable for passing to a completion handler.
  ASIO_DECL const asio::error_code &map_error_code(asio::error_code &ec) const {
    std::cout << "map_error_code(): Eh, I'm sure this one's fine" << std::endl;
    return _error_code;
  }

private:
  asio::error_code _error_code = asio::error::operation_not_supported;
};

} // namespace detail
} // namespace ssl
} // namespace asio

#endif // ASIO_SSL_DETAIL_LAZYSSL_ENGINE_HPP
