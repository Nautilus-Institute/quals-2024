defmodule GilroyWeb.TicketLive.Index do
  use GilroyWeb, :live_view

  alias Gilroy.Tickets

  @impl true
  def mount(_params, _session, socket) do
    {:ok, stream(socket, :tickets, Tickets.list_tickets())}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Listing Tickets")
    |> assign(:ticket, nil)
  end

  @impl true
  @spec handle_event(<<_::40>>, map(), Phoenix.LiveView.Socket.t()) :: {:noreply, map()}
  def handle_event("reset", %{"id" => id}, socket) do
    ticket = Tickets.get_ticket!(id)
    {:ok, updated_ticket} = Tickets.reset_ticket(ticket)

    {:noreply,
     socket
     |> stream_delete(:tickets, ticket)
     |> stream_insert(:tickets, updated_ticket)}
  end
end
