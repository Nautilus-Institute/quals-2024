defmodule GilroyWeb.TicketAuth do
  import Plug.Conn

  use GilroyWeb, :controller

  import Logger, warn: false

  alias Gilroy.Tickets

  @spec fetch_conn_ticket(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def fetch_conn_ticket(conn, _opts) do
    with ticket_id <- get_session(conn, :ticket_id),
         false <- is_nil(ticket_id),
         ticket = %Tickets.Ticket{} <-
           Tickets.get_ticket_without_database(ticket_id) do
      Logger.info("assigning conn ticket #{ticket.slug}")

      conn
      |> assign(:current_ticket, ticket)
      |> assign(:current_poster, nil)
    else
      _other ->
        Logger.info("no conn ticket")

        conn
        |> assign(:current_ticket, nil)
        |> assign(:current_poster, nil)
    end
  end

  def redirect_unless_user_is_authenticated(conn, _opts) do
    unless conn.assigns[:current_ticket] do
      conn
      |> redirect(to: ~p"/")
      |> halt()
    else
      conn
    end
  end

  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_ticket] do
      conn
      |> redirect(to: ~p"/dashboard")
      |> halt()
    else
      conn
    end
  end
end
