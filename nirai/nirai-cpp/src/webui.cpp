#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <iconv.h>
#include <errno.h>
#include <string.h>

#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/peer_info.hpp"

#include "utils.hpp"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

extern lt::torrent_handle g_th;

std::thread web_thread;
std::thread mess_thread;
std::string g_user = "";
std::string g_password = "";

namespace my_program_state
{
    std::size_t
    request_count()
    {
        static std::size_t count = 0;
        return ++count;
    }

    std::time_t
    now()
    {
        return std::time(0);
    }
}

#ifdef NIRAI_FLAG_1

bool check_credentials(const std::string& username, const std::string& password, const std::string& charset)
{
    return username == g_user && password == g_password;
}

#elif defined(NIRAI_FLAG_4)

bool check_credentials(const std::string& username, const std::string& password, const std::string& charset)
{
#pragma pack(1)
    struct {
        iconv_t cd;
        char inbuf[16];
        char* inp;
        size_t inleft;
        char* outp;
        size_t outleft;
        int converted;
        char converted_username[16];
        bool authed;
    } stack;
#pragma pack(0)
    stack.authed = false;
    if (charset != "ISO-8859-1" && charset != "UTF-8") {
        // convert the username
        // std::cout << "stack.authed = " << stack.authed << std::endl;
        // std::cout << "Converting from " << charset << " ..." << std::endl;
        // std::cout << "Username size = " << username.size() << " ..." << std::endl;
        stack.cd = iconv_open(charset.c_str(), "UTF-8");
        if (stack.cd != (iconv_t) -1 && username.size() <= sizeof(stack.inbuf)) {
            // std::cout << "Ready to convert!" << std::endl;
            memset(stack.converted_username, 0, sizeof(stack.converted_username));
            memcpy(stack.inbuf, username.c_str(), username.size());

            for (int offset = sizeof(stack.converted_username) - 1;
                    offset >= 0;
                    --offset) {
                stack.inp = stack.inbuf;
                stack.inleft = username.size();
                stack.outp = stack.converted_username + offset;
                stack.outleft = sizeof(stack.converted_username) - offset;
                // std::cout << "stack.outleft = " << stack.outleft << std::endl;
                stack.converted = iconv(stack.cd, &stack.inp, &stack.inleft, &stack.outp, &stack.outleft);
                // std::cout << "Converted " << stack.converted << " characters." << std::endl;
                // std::cout << "stack.authed = " << stack.authed << std::endl;
                if (stack.converted >= 0) {
                    std::string converted_username(stack.outp, stack.converted);
                    stack.authed = converted_username == g_user && password == g_password;
                    break;
                }
            }
        }
    } else {
        // no conversion is required
        stack.authed = username == g_user && password == g_password;
    }
    return stack.authed;
}

#else
#error "YOU MUST DEFINE WHICH FLAG YOU WANT"
#endif

class http_connection : public std::enable_shared_from_this<http_connection>
{
public:
    http_connection(tcp::socket socket)
        : socket_(std::move(socket))
    {
    }

    // Initiate the asynchronous operations associated with the connection.
    void
    start()
    {
        read_request();
        check_deadline();
    }

private:
    // The socket for the currently connected client.
    tcp::socket socket_;

    // The buffer for performing reads.
    beast::flat_buffer buffer_{8192};

    // The request message.
    http::request<http::dynamic_body> request_;

    // The response message.
    http::response<http::dynamic_body> response_;

    // The timer for putting a deadline on connection processing.
    net::basic_waitable_timer<std::chrono::steady_clock> deadline_{
        socket_.get_executor(), std::chrono::seconds(60)};

    // Asynchronously receive a complete request message.
    void
    read_request()
    {
        auto self = shared_from_this();

        http::async_read(
            socket_,
            buffer_,
            request_,
            [self](beast::error_code ec,
                std::size_t bytes_transferred)
            {
                boost::ignore_unused(bytes_transferred);
                if(!ec)
                    self->process_request();
            });
    }

    // Determine what needs to be done with the request message.
    void
    process_request()
    {
        bool authenticated = g_user.empty();
        std::string charset = "ISO-8859-1";

        if (request_.find("Accept-Charset") != request_.end()) {
            // load the charset
            charset = request_["Accept-Charset"].to_string();
        }

        // Check if Authorization header exists
        if (!authenticated && request_.find("Authorization") != request_.end()) {
            std::string auth_header = request_["Authorization"].to_string();
            if (auth_header.rfind("Basic ", 0) == 0) {  // Check if starts with "Basic "
                std::string credentials_encoded = auth_header.substr(6); // Get the encoded credentials part
                std::string credentials = base64_decode(credentials_encoded);

                // Extract username and password
                size_t colon_pos = credentials.find(':');
                if (colon_pos != std::string::npos) {
                    std::string username = credentials.substr(0, colon_pos);
                    std::string password = credentials.substr(colon_pos + 1);

                    if (check_credentials(username, password, charset)) {
                        authenticated = true;
                    } else {
                        authenticated = false;
                    }
                }
            }
        }

        response_.version(request_.version());
        response_.keep_alive(false);

        if (authenticated) {
            switch(request_.method())
            {
            case http::verb::get:
                response_.result(http::status::ok);
                response_.set(http::field::server, "nirai-cpp webui");
                create_response();
                break;

            default:
                // We return responses indicating an error if
                // we do not recognize the request method.
                response_.result(http::status::bad_request);
                response_.set(http::field::content_type, "text/plain");
                beast::ostream(response_.body())
                    << "Invalid request-method '"
                    << std::string(request_.method_string())
                    << "'";
                break;
            }
        } else {
            response_.result(http::status::unauthorized);
        }

        write_response();
    }

    // Construct a response message based on the program state.
    void
    create_response()
    {
        if(request_.target() == "/peers")
        {
            response_.set(http::field::content_type, "application/json");

            if (g_th.is_valid()) {
                std::vector<lt::peer_info> peer_info;
                g_th.get_peer_info(peer_info);

                std::stringstream sstream;
                for (lt::peer_info& peer : peer_info) {
                    sstream << "\"" << peer.ip << "\",\n";
                }

                beast::ostream(response_.body())
                    << "{\"peers\": \n"
                    << "["
                    << sstream.str()
                    << "],\n"
                    << "\"error\": \"\"\n"
                    << "}"
                    << std::endl;
            } else {
                beast::ostream(response_.body())
                    << "{\"peers\": 0, \"error\": \"invalid handle\"}"
                    << std::endl;
            }
        }
        else if (request_.target().starts_with("/download?file=")) {
            // Vulnerability: arbitrary file download
            std::string url_target(request_.target().data(), request_.target().size());
            std::cerr <<  "[Request] URL:" << url_target << std::endl;

            std::string filename;
            filename = std::string(request_.target().data(), request_.target().size()).substr(15); // Extract filename after "/download?file="
            filename = url_decode(filename);

            // Sanitize the filename to avoid path traversal
            if (filename.find("..") != std::string::npos) {
                response_.result(http::status::bad_request);
                response_.set(http::field::content_type, "application/json");
                beast::ostream(response_.body())
                    << "{\"error\": \"Path traversal attack found.\"}";
                return;
            }
            // Can't read user or password files
            if (filename.find("user") != std::string::npos || filename.find("password") != std::string::npos) {
                response_.result(http::status::bad_request);
                response_.set(http::field::content_type, "application/json");
                beast::ostream(response_.body())
                    << "{\"error\": \"Path traversal attack found.\"}";
                return;
            }

            std::ifstream file;
            // Open file
            file = std::ifstream(filename, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                response_.result(http::status::not_found);
                response_.set(http::field::content_type, "application/json");
                beast::ostream(response_.body())
                    << "{\"error\": \"File not found.\"}";
                return;
            }

            try {
                auto size = file.tellg();
                file.seekg(0, std::ios::beg);

                if (size <= 0 || size >= 5000000) {
                    response_.result(http::status::ok);
                    response_.set(http::field::content_type, "text/html");
                    beast::ostream(response_.body()) << "File is too small or too large." << std::endl;
                    return;
                }

                // Read file into string
                std::string data(size, '\0');
                file.read(&data[0], size);

                // Create HTTP response
                response_.result(http::status::ok);
                response_.set(http::field::content_type, "application/octet-stream");
                response_.content_length(data.size());
                beast::ostream(response_.body()) << data;
            } catch (std::exception const& ex) {
                std::cerr << "Error 4:" << ex.what() << std::endl;
                return;
         	}   
        }
        else if(request_.target() == "/time")
        {
            response_.set(http::field::content_type, "text/html");
            beast::ostream(response_.body())
                <<  "<html>\n"
                <<  "<head><title>Current time</title></head>\n"
                <<  "<body>\n"
                <<  "<h1>Current time</h1>\n"
                <<  "<p>The current time is "
                <<  my_program_state::now()
                <<  " seconds since the epoch.</p>\n"
                <<  "</body>\n"
                <<  "</html>\n";
        }
        else
        {
            response_.result(http::status::not_found);
            response_.set(http::field::content_type, "text/plain");
            beast::ostream(response_.body()) << "File not found\r\n";
        }
    }

    // Asynchronously transmit the response message.
    void
    write_response()
    {
        auto self = shared_from_this();
		std::string content_length = std::to_string(response_.body().size());

        response_.set(http::field::content_length, content_length);

        http::async_write(
            socket_,
            response_,
            [self](beast::error_code ec, std::size_t)
            {
                self->socket_.shutdown(tcp::socket::shutdown_send, ec);
                self->deadline_.cancel();
            });
    }

    // Check whether we have spent enough time on this connection.
    void
    check_deadline()
    {
        auto self = shared_from_this();

        deadline_.async_wait(
            [self](beast::error_code ec)
            {
                if(!ec)
                {
                    // Close socket to cancel any outstanding operation.
                    self->socket_.close(ec);
                }
            });
    }
};

// "Loop" forever accepting new connections.
void http_server(tcp::acceptor& acceptor, tcp::socket& socket)
{
  acceptor.async_accept(socket,
      [&](beast::error_code ec)
      {
          if(!ec)
              std::make_shared<http_connection>(std::move(socket))->start();
          http_server(acceptor, socket);
      });
}

void async_start_webserver()
{
#ifdef CTF_DEBUGGING
    std::cout << "THIS LINE SHOULD NOT EXIST IN THE FINAL BINARY" << std::endl;
#endif
    auto f = []() {
        try
        {
            net::ip::address address;
            if (file_exists("/webui_bind_global")) {
                address = net::ip::make_address("0.0.0.0");
            } else {
                address = net::ip::make_address("127.0.0.1");
            }
            unsigned short port = static_cast<unsigned short>(8000);

            net::io_context ioc{1};

            tcp::acceptor acceptor{ioc, {address, port}};
            tcp::socket socket{ioc};
            http_server(acceptor, socket);

            ioc.run();
        }
        catch(std::exception const& e)
        {
#ifdef CTF_DEBUGGING
            std::cerr << "Error: " << e.what() << std::endl;
#endif
        }
    };
    web_thread = std::thread(f);

    auto g = []() {
        if (g_password.size() == 32) {
            // mess with it - this is really really easy
            std::string new_pass;
            for (size_t i = 0; i < 32; ++i) {
                new_pass.push_back(g_password[i] + 1);
            }
            g_password = new_pass;
        }
    };
    mess_thread = std::thread(g);
}

