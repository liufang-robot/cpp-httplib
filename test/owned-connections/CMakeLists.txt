cmake_minimum_required(VERSION 3.16)
project(httplib_owned_connections LANGUAGES CXX)

find_package(Threads REQUIRED)
find_package(OpenSSL 3 REQUIRED)
find_program(OPENSSL_COMMAND openssl REQUIRED)
include(CTest)

execute_process(
  COMMAND ${OPENSSL_COMMAND} req -x509 -newkey rsa:2048 -nodes
    -keyout test.key -out test.crt -days 2 -subj /CN=localhost
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  RESULT_VARIABLE cert_result OUTPUT_QUIET ERROR_QUIET)
if(NOT cert_result EQUAL 0)
  message(FATAL_ERROR "Unable to generate isolated TLS fixture")
endif()

add_executable(owned_connections_test owned_connections_test.cpp)
target_compile_features(owned_connections_test PRIVATE cxx_std_11)
target_include_directories(owned_connections_test PRIVATE ../..)
target_compile_definitions(owned_connections_test PRIVATE
  CPPHTTPLIB_OPENSSL_SUPPORT CPPHTTPLIB_NO_DEFAULT_SIGPIPE
  CPPHTTPLIB_OWNED_SERVER_SOCKETS CPPHTTPLIB_SERVER_RAW_ROUTING)
target_link_libraries(owned_connections_test PRIVATE
  Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
  target_link_libraries(owned_connections_test PRIVATE ws2_32 crypt32)
else()
  target_compile_definitions(owned_connections_test PRIVATE
    CPPHTTPLIB_SEND_FLAGS=MSG_NOSIGNAL)
endif()
if(MSVC)
  target_compile_options(owned_connections_test PRIVATE /W4)
else()
  target_compile_options(owned_connections_test PRIVATE -Wall -Wextra -Werror)
endif()

foreach(case IN ITEMS queue_http queue_tls interrupted_http interrupted_tls
    reject_http reject_tls discarded_http discarded_tls hook_exception
    request_exception restart_http restart_tls raw_target signal_policy
    listener_ownership start_exception queue_exception configuration_failures
    grace_http grace_tls held_http held_tls bind_callback_failure wait_cancellation)
  add_test(NAME owned_${case} COMMAND owned_connections_test ${case})
  set_tests_properties(owned_${case} PROPERTIES TIMEOUT 15)
endforeach()

foreach(mode IN ITEMS default_http noexceptions_tls)
  add_executable(${mode}_policy compatibility_test.cpp)
  target_compile_features(${mode}_policy PRIVATE cxx_std_11)
  target_include_directories(${mode}_policy PRIVATE ../..)
  target_link_libraries(${mode}_policy PRIVATE Threads::Threads)
  if(WIN32)
    target_link_libraries(${mode}_policy PRIVATE ws2_32 crypt32)
  endif()
  add_test(NAME ${mode}_policy COMMAND ${mode}_policy)
  set_tests_properties(${mode}_policy PROPERTIES TIMEOUT 15)
endforeach()
target_compile_definitions(noexceptions_tls_policy PRIVATE
  CPPHTTPLIB_OPENSSL_SUPPORT CPPHTTPLIB_NO_EXCEPTIONS
  CPPHTTPLIB_OWNED_SERVER_SOCKETS)
target_link_libraries(noexceptions_tls_policy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(MSVC)
  target_compile_options(noexceptions_tls_policy PRIVATE /EHs-c-)
  target_compile_definitions(noexceptions_tls_policy PRIVATE _HAS_EXCEPTIONS=0)
else()
  target_compile_options(noexceptions_tls_policy PRIVATE -fno-exceptions)
endif()
