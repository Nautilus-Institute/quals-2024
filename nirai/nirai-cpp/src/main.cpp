#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>

#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/torrent_info.hpp"

#include "webui.hpp"
#include "utils.hpp"

extern std::string g_user;
extern std::string g_password;

char torrent_data_base64[] = 
    "ZDg6YW5ub3VuY2U0Mjp1ZHA6Ly90cmFja2VyLm9wZW50cmFja3Iub3JnOjEzMzcvYW5ub3VuY2U3"
    "OmNvbW1lbnQyNjpGb3IgYm9vdHN0cmFwcGluZyBwdXJwb3NlczEwOmNyZWF0ZWQgYnkxODpxQml0"
    "dG9ycmVudCB2NC42LjQxMzpjcmVhdGlvbiBkYXRlaTE3MTQ3MjQ4ODllNDppbmZvZDY6bGVuZ3Ro"
    "aTEwNDg1NzYwMGU0Om5hbWUxMzpib290c3RyYXAuYmluMTI6cGllY2UgbGVuZ3RoaTgzODg2MDhl"
    "NjpwaWVjZXMyNjA6COsY1AOMDCNOjFZbomhIoKYnSWKskTQn9zDYl/ximNKvkkCwyrKhc+17NLZV"
    "+7p8y/iIgb4DkLGvg8c+dJKxIIQIUck+iRtk2ilru33KTTGtsrOkL+JbAiPfjaKqJ3yqrurY+lqG"
    "OodePcer/4ZjAlcmVMMbKxayfP7U9u9ZbjcCifAskVDGdcLO0mXwCN/2MvQJW8vfH5sbIqvjnt0/"
    "OWAAaQyb/Orfm/fxIVOwmpnGCcwohvHn2uvzP/NRtV3YPAPOBryfqgRR0x0afuz0whN7WLl66dtm"
    "KtbcgMu3yyJWlbUdeycIlUbwsmFhG0sDIN3d/BRg/kT7kEELsM7HGadv2BU3OnByaXZhdGVpMWVl"
    "ZQ==";

lt::torrent_handle g_th;

void connect_to_network()
{
    try
    {
        std::string torrent_data = base64_decode(std::string(torrent_data_base64));

        lt::session s;

        lt::settings_pack settings;
#ifdef NIRAI_FLAG_1
        settings.set_str(lt::settings_pack::user_agent, "nirai-cpp v1");
#elif defined(NIRAI_FLAG_4)
        settings.set_str(lt::settings_pack::user_agent, "nirai-cpp v2");
#else
#error "YOU MUST DEFINE FLAG_1 or FLAG_4"
#endif
        s.apply_settings(settings);

        lt::add_torrent_params p;
        p.save_path = "/tmp/";
        p.ti = std::make_shared<lt::torrent_info>(torrent_data.c_str(), torrent_data.size());
        g_th = s.add_torrent(p);
        g_th.set_download_limit(5000);
        g_th.set_upload_limit(5000);
        auto status = g_th.status();

        while (not status.is_seeding) {
            status = g_th.status();
            sleep(5);
        }
        return;
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << std::endl;
        throw e;
    }
}

int main(int argc, char* argv[])
{
    // start the webserver
    
    // load the credentials for the webserver
    try {
        std::ifstream user("/web_server_user");
        if (!user) {
            throw new std::exception();
        }
        std::ifstream password("/web_server_password");
        if (!password) {
            throw new std::exception();
        }
        getline(user, g_user);
        getline(password, g_password);
        password.close();
        user.close();
    } catch (...) {
        g_user = "nirai_admin";
        g_password = "F16D2EBFEFD4C26CB2F676229ED58F26";
    }

    if (file_exists("/web_server")) {
        async_start_webserver();
    }

    connect_to_network();
}
