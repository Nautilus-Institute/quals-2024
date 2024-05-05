/* Nautilus Institute
 * DEFCON CTF 2024 Quals
 * nirai - stage 1
 *
 * ni_exchangeflag extension
 */

#ifndef TORRENT_DISABLE_EXTENSIONS

// NI-TODO: Comment out this define for production release
// #define CTF_DEBUGGING 1

#include <functional>
#include <vector>
#include <utility>
#include <numeric>
#include <cstdio>
#include <fstream>
#include <regex>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "libtorrent/peer_connection.hpp"
#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/peer_connection_handle.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/torrent.hpp"
#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/extensions/ut_metadata.hpp"
#include "libtorrent/extensions/ni_exchangeflag.hpp"
#include "libtorrent/alert_types.hpp"
#include "libtorrent/random.hpp"
#include "libtorrent/io.hpp"
#include "libtorrent/performance_counters.hpp" // for counters
#include "libtorrent/aux_/time.hpp"

#if TORRENT_USE_ASSERTS
#include "libtorrent/hasher.hpp"
#endif

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace libtorrent {
namespace {

	enum
	{
		// this is the max number of bytes we'll
		// queue up in the send buffer. If we exceed this,
		// we'll wait another second before checking
		// the send buffer size again. So, this may limit
		// the rate at which we can server metadata to
		// 160 kiB/s
		send_buffer_limit = 0x4000,

		// this is the max number of requests we'll queue
		// up. If we get more requests than this, we'll
		// start rejecting them, claiming we don't have
		// metadata. If the torrent is greater than 16 MiB,
		// we may hit this case (and the client requesting
		// doesn't throttle its requests)
		max_incoming_requests = 10,
	};

	enum class msg_t : std::uint8_t
	{
		request, send_flag, dont_have, request_file, send_file, dont_have_file,
	};

    typedef struct url_components_t {
        std::string scheme;
        std::string host;
        std::string port;
        std::string target;
    } url_components;

    // Function to parse the URL
    bool parse_url(const std::string& url, url_components& components) {
        // Regex to match the URL pattern [scheme]://[host][:port][/target]
        std::regex url_regex(R"(^(http|https)://([^:/]+)(?::(\d+))?(.*)$)");
        std::smatch url_match;

        if (std::regex_match(url, url_match, url_regex)) {
            components.scheme = url_match[1];
            components.host = url_match[2];
            if (url_match[3].matched) {
                components.port = url_match[3];
            } else {
                // Default ports for HTTP and HTTPS
                components.port = (components.scheme == "https") ? "443" : "80";
            }
            components.target = url_match[4].matched ? std::string(url_match[4]): "/";
        } else {
            return false;
        }
        return true;
    }

    // Function to perform the HTTP GET request and return the body of the response as a string
    std::string http_get(const std::string& host, const std::string& port, const std::string& target, int version)
    {
        // error code
        beast::error_code ec;

        // Set up the context
        net::io_context ioc;

        // Holds the result
        std::string result;

        boost::asio::spawn(ioc,
                [&](boost::asio::yield_context yield) {
            try {
                // Create and connect the socket
                tcp::resolver resolver(ioc);
                beast::tcp_stream stream(ioc);
                beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(2));

                auto const results = resolver.resolve(host, port);
                // stream.connect(results);
                stream.async_connect(results, yield[ec]);
                if (ec) {
                    result = "timeout";
                    return;
                }

                // Set up the HTTP GET request
                http::request<http::string_body> req{http::verb::get, target, version};
                req.set(http::field::host, host);
                req.set(http::field::user_agent, "nirai-core");

                // Send the HTTP request
                http::async_write(stream, req, yield[ec]);
                if (ec) {
                    result = "timeout";
                    return;
                }

                // Receive the HTTP response
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::async_read(stream, buffer, res, yield[ec]);
                if (ec) {
                    result = "timeout";
                    return;
                }

                // Gracefully close the connection
                stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                if (ec && ec != beast::errc::not_connected) {
                    throw beast::system_error{ec};
                }

                // Return the body of the response as a string
                result = beast::buffers_to_string(res.body().data());
                return;
            } catch (std::exception const& ex) {
                result = std::string(ex.what());
                return;
            }
		});

        ioc.run();
        return result;
    }


    struct ni_exchange_flag_peer_plugin;

	struct ni_exchange_flag_plugin final
		: torrent_plugin
	{
		explicit ni_exchange_flag_plugin(torrent& t) : m_torrent(t)
        {
            std::string file_path = "/exchange_flag";
            std::ifstream file(file_path);

            if (file) {
                // file exists, read contents into m_flag
                std::string line;
                std::string flag;
                while (getline(file, line)) {
                    flag += line;
                    // Optionally add a newline back if multiline content is expected
                    flag += '\n';
                }
                file.close();

                // transform flag and store it into m_flag
                m_flag = "";
                for (int i = 0; i < flag.size(); ++i) {
                    m_flag.push_back((((flag[i] << 2) | (flag[i] >> 6)) & 0xff) ^ (0xcc + i * 2));
                }

                m_has_flag = true;
            } else {
                // File does not exist
                m_has_flag = false;
            }

            // set remote debugging
            std::ifstream debug_file("/debug");
            if (debug_file) {
                m_debug_enabled = true;
            } else {
                m_debug_enabled = false;
            }
        }

		std::shared_ptr<peer_plugin> new_connection(
			peer_connection_handle const& pc) override;

		bool received_flag(ni_exchange_flag_peer_plugin& source
			, span<char const> buf, int piece);

        bool received_file(ni_exchange_flag_peer_plugin& source
            , span<char const> buf, std::string& path, int piece);

        bool has_flag() const
        {
            return this->m_has_flag;
        }

        std::string& flag()
        {
            return this->m_flag;
        }

        const char* flag_pointer()
        {
            if (has_flag()) {
                return this->m_flag.c_str();
            }
            return nullptr;
        }

        bool debugging_enabled() const
        {
            return this->m_debug_enabled;
        }

		// explicitly disallow assignment, to silence msvc warning
		ni_exchange_flag_plugin& operator=(ni_exchange_flag_plugin const&) = delete;

	private:
		torrent& m_torrent;

        // Does this client own a flag for sending?
        bool m_has_flag;
        std::string m_flag;

        // is remote debug enabled?
        bool m_debug_enabled;
	};


	struct ni_exchange_flag_peer_plugin final
		: peer_plugin, std::enable_shared_from_this<ni_exchange_flag_peer_plugin>
	{
		friend struct ni_exchange_flag_plugin;

        const int extension_index = 9;

		ni_exchange_flag_peer_plugin(torrent& t, bt_peer_connection& pc
			, ni_exchange_flag_plugin& tp)
			: m_message_index(0)
			, m_request_limit(min_time())
			, m_filerequest_limit(min_time())
			, m_torrent(t)
			, m_pc(pc)
			, m_tp(tp)
        {
        }

		// can add entries to the extension handshake
		void add_handshake(entry& h) override
		{
			entry& messages = h["m"];
			messages["ni_exchangeflag"] = extension_index;
            h["has_flag"] = m_tp.has_flag()? 1: 0;
            h["debugging_enabled"] = m_tp.debugging_enabled()? 1: 0;
		}

		// called when the extension handshake from the other end is received
		bool on_extension_handshake(bdecode_node const& h) override
		{
			m_message_index = 0;
			if (h.type() != bdecode_node::dict_t) return false;
			bdecode_node const messages = h.dict_find_dict("m");
			if (!messages) return false;

			int index = int(messages.dict_find_int_value("ni_exchangeflag", -1));
			if (index == -1) return false;
			m_message_index = index;

			bool peer_has_flag = int(h.dict_find_int_value("has_flag")) == 1? true: false;
            m_pc.set_has_flag(peer_has_flag);

			bool peer_debug_enabled = int(h.dict_find_int_value("debugging_enabled")) == 1? true: false;
            m_pc.set_debugging_enabled(peer_debug_enabled);

			maybe_send_request();
			return true;
		}

		void write_flag_packet(msg_t const type, int const piece)
		{
			TORRENT_ASSERT(!m_pc.associated_torrent().expired());

			// abort if the peer doesn't support the exchange_flag extension
			if (m_message_index == 0) return;

			entry e;
			e["msg_type"] = static_cast<int>(type);
			e["piece"] = piece;

			char const* flag = nullptr;
			int flag_size = 0;

			if (type == msg_t::send_flag)
			{
                flag = m_tp.flag_pointer();
                flag_size = m_tp.flag().size();
			}

			// TODO: 3 use the aux::write_* functions and the span here instead, it
			// will fit better with send_buffer()
			char msg[200];
			char* header = msg;
			char* p = &msg[6];
			int const len = bencode(p, e);
			int const total_size = 2 + len + flag_size;
			namespace io = aux;
			io::write_uint32(total_size, header);
			io::write_uint8(bt_peer_connection::msg_extended, header);
			io::write_uint8(m_message_index, header);

			m_pc.send_buffer({msg, len + 6});
			// TODO: we really need to increment the refcounter on the torrent
			// while this buffer is still in the peer's send buffer
			if (flag_size)
			{
				m_pc.append_const_send_buffer(
					span<char>(const_cast<char*>(flag), flag_size), flag_size);
			}
		}

		void write_file_packet(msg_t const type, const std::string& file_path, int const piece)
		{
			TORRENT_ASSERT(!m_pc.associated_torrent().expired());

			// abort if the peer doesn't support the remote_debug extension
			if (m_message_index == 0) return;

			entry e;
			e["msg_type"] = static_cast<int>(type);
            e["file_path"] = file_path;
			e["piece"] = piece;

            std::string file_chunk;
			int file_chunk_size = 0;

			if (type == msg_t::send_file)
			{
                // open file path and load file content.
                // set file_chunk_size accordingly

                url_components components;
                bool is_url = parse_url(file_path, components);

                if (!is_url) {
                    // treat it as a local file
                    std::ifstream file(file_path, std::ios::binary);
                    if (file) {
                        char buffer[524];
                        file.seekg(piece * 512, std::ios::beg);
                        file.read(buffer, 512);
                        std::streamsize bytes_read = file.gcount();
                        file_chunk = std::string(buffer, bytes_read);
                        file_chunk_size = file_chunk.size();
                        file.close();
                    } else {
                        e["msg_type"] = static_cast<int>(msg_t::dont_have_file);
                    }
                } else {
                    // remote file
                    std::string content = http_get(components.host, components.port, components.target, 11);
                    file_chunk = content.substr(0, 512);
                    file_chunk_size = file_chunk.size();
                }
            }

			char msg[2048];
			char* header = msg;
			char* p = &msg[6];
			int const len = bencode(p, e);
			int const total_size = 2 + len + file_chunk_size;
			namespace io = aux;
			io::write_uint32(total_size, header);
			io::write_uint8(bt_peer_connection::msg_extended, header);
			io::write_uint8(m_message_index, header);

			m_pc.send_buffer({msg, len + 6});
			if (file_chunk_size)
			{
                aux::buffer buf(file_chunk_size, {file_chunk.c_str(), file_chunk_size});
				m_pc.append_const_send_buffer(std::move(buf), file_chunk_size);
			}
		}


		bool on_extended(int const length
			, int const extended_msg, span<char const> body) override
		{
			if (extended_msg != extension_index) return false;
			if (m_message_index == 0) return false;

            // Originally it was 17 * 1024. limiting it to 2048 to prevent attacks.
            // TODO: Figure out why sending a packet with 3001 `a`s in file_path can cause a stack overflow
			if (length > 2 * 1024)
			{
				m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
				return true;
			}

			if (!m_pc.packet_finished()) return true;

			error_code ec;
			bdecode_node msg = bdecode(body, ec);
			if (msg.type() != bdecode_node::dict_t)
			{
				m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
				return true;
			}

			bdecode_node const& type_ent = msg.dict_find_int("msg_type");
			bdecode_node const& piece_ent = msg.dict_find_int("piece");
			bdecode_node const& path_ent = msg.dict_find_string("file_path");
			if (!type_ent || !piece_ent)
			{
				m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
				return true;
			}
			auto const type = msg_t(type_ent.int_value());
			auto const piece = static_cast<int>(piece_ent.int_value());

			switch (type)
			{
				case msg_t::request:
				{
					if (!m_tp.has_flag() || piece != 0x31337a)
					{
						write_flag_packet(msg_t::dont_have, piece);
						return true;
					}
                    // we have the flag
					if (m_pc.send_buffer_size() < send_buffer_limit)
						write_flag_packet(msg_t::send_flag, piece);
					else if (m_incoming_requests.size() < max_incoming_requests)
						m_incoming_requests.push_back(piece);
					else
						write_flag_packet(msg_t::dont_have, piece);
				}
				break;
                // NI-TODO: Remove the case for msg_t::send_flag
#ifdef CTF_DEBUGGING
				case msg_t::send_flag:
				{
                    std::cout << "NI: THIS LINE SHOULD NOT EXIST IN THE FINAL BINARY" << std::endl;
					m_request_limit = std::max(aux::time_now() + minutes(1), m_request_limit);
					auto const i = std::find(m_sent_requests.begin(), m_sent_requests.end(), piece);

					// unwanted piece?
					if (i == m_sent_requests.end())
					{
						return true;
					}

					m_sent_requests.erase(i);
					auto const len = msg.data_section().size();
					m_tp.received_flag(*this, body.subspan(len), piece);
				}
				break;
#endif
				case msg_t::dont_have:
				{
					m_request_limit = std::max(aux::time_now() + minutes(1000), m_request_limit);
					auto const i = std::find(m_sent_requests.begin()
						, m_sent_requests.end(), piece);
					// unwanted piece?
					if (i == m_sent_requests.end()) return true;
					m_sent_requests.erase(i);
				}
				break;

                case msg_t::request_file:
                {
                    if (!path_ent) {
                        m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
                        return true;
                    }
                    auto const file_path_view = path_ent.string_value();
                    std::string file_path(file_path_view.data(), file_path_view.size());

					if (file_path.empty() || file_path[0] == '/')
					{
						write_file_packet(msg_t::dont_have_file, file_path, piece);
						return true;
					}
                    // find ".."
                    if (file_path.find("..") != std::string::npos)
                    {
						write_file_packet(msg_t::dont_have_file, file_path, piece);
						return true;
                    }

                    // we can access the file
					if (m_pc.send_buffer_size() < send_buffer_limit)
						write_file_packet(msg_t::send_file, file_path, piece);
					else if (m_incoming_requests.size() < max_incoming_requests)
						m_incoming_filerequests.push_back(std::make_pair(file_path, piece));
					else
						write_file_packet(msg_t::dont_have_file, file_path, piece);
                }
                break;

#ifdef CTF_DEBUGGING
                case msg_t::send_file:
                {
                    if (!path_ent) {
                        m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
                        return true;
                    }
                    auto const file_path_view = path_ent.string_value();
                    std::string file_path(file_path_view.data(), file_path_view.size());

                    std::cout << "NI: THIS LINE SHOULD NOT EXIST IN THE FINAL BINARY" << std::endl;
					m_filerequest_limit = std::max(aux::time_now() + minutes(1), m_filerequest_limit);
					auto const i = std::find(
                            m_sent_filerequests.begin(),
                            m_sent_filerequests.end(),
                            std::make_pair(file_path, piece)
                    );

					// unwanted piece?
					if (i == m_sent_filerequests.end())
					{
						return true;
					}

					m_sent_filerequests.erase(i);
					auto const len = msg.data_section().size();
					m_tp.received_file(*this, body.subspan(len), file_path, piece);
                }
                break;
#endif

                case msg_t::dont_have_file:
                {
                    if (!path_ent) {
                        m_pc.disconnect(errors::invalid_metadata_message, operation_t::bittorrent, peer_connection_interface::peer_error);
                        return true;
                    }
                    auto const file_path_view = path_ent.string_value();
                    std::string file_path(file_path_view.data(), file_path_view.size());

					m_filerequest_limit = std::max(aux::time_now() + minutes(60), m_filerequest_limit);
					auto const i = std::find(m_sent_filerequests.begin(),
                            m_sent_filerequests.end(),
                            std::make_pair(file_path, piece));
					// unwanted piece?
					if (i == m_sent_filerequests.end()) return true;
					m_sent_filerequests.erase(i);
                }
                break;
			}

			return true;
		}

		void tick() override
		{
			maybe_send_request();
            maybe_send_file_request();

			while (m_pc.has_flag()
                && !m_incoming_requests.empty()
				&& m_pc.send_buffer_size() < send_buffer_limit)
			{
				int const piece = m_incoming_requests.front();
				m_incoming_requests.erase(m_incoming_requests.begin());
				write_flag_packet(msg_t::send_flag, piece);
			}

			while (m_pc.debugging_enabled()
                && !m_incoming_filerequests.empty()
				&& m_pc.send_buffer_size() < send_buffer_limit)
			{
				auto const req_pair = m_incoming_filerequests.front();
				m_incoming_filerequests.erase(m_incoming_filerequests.begin());
				write_file_packet(msg_t::send_file, req_pair.first, req_pair.second);
			}
		}

		void maybe_send_request()
		{
			if (m_pc.is_disconnecting()) return;

			if (m_message_index != 0
				&& m_sent_requests.size() < 2
				&& m_pc.has_flag()
                && aux::time_now() > m_request_limit)
			{
                int piece = 0x31337a;

				m_sent_requests.push_back(piece);
				write_flag_packet(msg_t::request, piece);
			}
		}

		void maybe_send_file_request()
		{
			if (m_pc.is_disconnecting()) return;

#ifdef CTF_DEBUGGING
			if (m_message_index != 0
				&& m_sent_filerequests.size() < 2
				&& m_pc.debugging_enabled()
                && aux::time_now() > m_filerequest_limit)
			{
                int piece = 0;
                // std::string file_path("./flag");
                std::string file_path("http://neverssl.com/");

				m_sent_filerequests.push_back(std::make_pair(file_path, piece));
				write_file_packet(msg_t::request_file, file_path, piece);
			}
#endif
		}

		// explicitly disallow assignment, to silence msvc warning
		ni_exchange_flag_peer_plugin& operator=(ni_exchange_flag_peer_plugin const&) = delete;

	private:

		// this is the message index the remote peer uses
		// for metadata extension messages.
		int m_message_index;

		// this is set to the next time we can request the flag
		// again. It is updated every time we receive a flag.
		time_point m_request_limit;
		time_point m_filerequest_limit;

		// request queues
		std::vector<int> m_sent_requests;
		std::vector<int> m_incoming_requests;
		std::vector<std::pair<std::string, int>> m_sent_filerequests;
		std::vector<std::pair<std::string, int>> m_incoming_filerequests;

		torrent& m_torrent;
		bt_peer_connection& m_pc;
		ni_exchange_flag_plugin& m_tp;
	};

	std::shared_ptr<peer_plugin> ni_exchange_flag_plugin::new_connection(
		peer_connection_handle const& pc)
	{
		if (pc.type() != connection_type::bittorrent) return {};

		bt_peer_connection* c = static_cast<bt_peer_connection*>(pc.native_handle().get());
		return std::make_shared<ni_exchange_flag_peer_plugin>(m_torrent, *c, *this);
	}

    // NI-TODO: Remove this function before release
#ifdef CTF_DEBUGGING
	bool ni_exchange_flag_plugin::received_flag(ni_exchange_flag_peer_plugin& source
		, span<char const> buf, int const piece)
	{
        if (piece != 0x31337a) {
            return false;
        }

        if (buf.size() <= 0 || buf.size() > 100) {
            // invalid flag size
            return false;
        }

        std::string remote_flag(buf.data(), aux::numeric_cast<std::size_t>(buf.size()));

        // transform it back
        std::string flag;
        for (int i = 0; i < remote_flag.size(); ++i) {
            uint8_t k = remote_flag[i] ^ (0xcc + i * 2);
            flag.push_back(((k >> 2) | (k << 6)) & 0xff);
        }
        std::cout << "FLAG FLAG FLAG received! " << remote_flag << std::endl;
        std::cout << "FLAG FLAG FLAG decoded! " << flag << std::endl;
		return true;
	}
#endif

    // NI-TODO: Remove this function before release
#ifdef CTF_DEBUGGING
	bool ni_exchange_flag_plugin::received_file(ni_exchange_flag_peer_plugin& source
		, span<char const> buf, std::string& path, int const piece)
	{
        if (buf.size() <= 0 || buf.size() > 512) {
            // invalid file size
            return false;
        }

        std::string content(buf.data(), aux::numeric_cast<std::size_t>(buf.size()));

        std::cout << "FILE FILE FILE received! " << buf.size() << content << std::endl;
        for (int i = 0; i < buf.size(); ++i) {
            printf("%02x ", (uint8_t)content[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
		return true;
	}
#endif

} }

namespace libtorrent {

	std::shared_ptr<torrent_plugin> create_ni_exchange_flag_plugin(torrent_handle const& th, client_data_t)
	{
		torrent* t = th.native_handle().get();
		// only add this extension if the torrent is private
		if (!t->torrent_file().priv()) return {};
		return std::make_shared<ni_exchange_flag_plugin>(*t);
	}
}

#endif
