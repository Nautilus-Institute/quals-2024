#ifndef TORRENT_NI_EXCHANGEFLAG_HPP_INCLUDED
#define TORRENT_NI_EXCHANGEFLAG_HPP_INCLUDED

#ifndef TORRENT_DISABLE_EXTENSIONS

#include "libtorrent/config.hpp"

#include <memory>

namespace libtorrent {

	struct torrent_plugin;
	struct torrent_handle;
	struct client_data_t;

	TORRENT_EXPORT std::shared_ptr<torrent_plugin> create_ni_exchange_flag_plugin(torrent_handle const&, client_data_t);
}

#endif // TORRENT_DISABLE_EXTENSIONS
#endif // TORRENT_NI_EXCHANGEFLAG_HPP_INCLUDED
