defmodule GilroyWeb.TicketsControllerTest do
  use GilroyWeb.ConnCase

  setup %{conn: conn} do
    ticket =
      CtfTickets.Ticket.initialize(
        Application.get_env(:gilroy, Gilroy.Tickets)[:challenge_secret_key],
        "GilroyTestTicket#{:rand.uniform(1_000_000_000)}"
      )

    ser = CtfTickets.Ticket.serialize(ticket)

    %CtfTickets.Ticket{} ==
      CtfTickets.Ticket.deserialize(
        Application.get_env(:gilroy, Gilroy.Tickets)[:challenge_secret_key],
        ser
      )

    {:ok,
     %{
       ticket: ticket,
       serialized: ser
     }}
  end

  test "POST /tickets", %{conn: conn, serialized: ser} do
    conn = post(conn, "/tickets", %{"encrypted_ticket" => ser})
    refute redirected_to(conn) == "/"
  end
end
