defmodule GilroyWeb.TicketLive.Show do
  use GilroyWeb, :live_view

  alias Gilroy.Tickets

  import Logger, warn: false

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket}
  end

  @impl true
  def handle_params(%{"id" => id}, _, socket) do
    {:noreply,
     socket
     |> assign(:page_title, page_title(socket.assigns.live_action))
     |> assign(:ticket, Tickets.get_ticket_without_database!(id))}
  end

  defp page_title(:show), do: "Show Ticket"
end
