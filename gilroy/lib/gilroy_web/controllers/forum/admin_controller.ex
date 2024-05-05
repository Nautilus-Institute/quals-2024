defmodule GilroyWeb.Forum.AdminController do
  use GilroyWeb, :controller

  import Logger, warn: false

  def index(conn, _params) do
    ip = conn.remote_ip
    ticket = conn.assigns.current_ticket

    receipt =
      Gilroy.Tickets.to_flag(ticket, ip) ||
        "couldn't get a ticket, please tell an admin"

    render(conn, "index.html", receipt: receipt)
  end
end
