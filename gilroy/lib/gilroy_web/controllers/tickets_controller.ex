defmodule GilroyWeb.TicketsController do
  use GilroyWeb, :controller

  import Logger, warn: false

  alias Gilroy.Tickets

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{"encrypted_ticket" => enc} = _params) do
    case enc |> String.trim() |> Tickets.upsert_ticket() do
      _db_tix = %Tickets.Ticket{id: ticket_id} ->
        Logger.info("accepted ticket #{inspect(enc)} as #{inspect(ticket_id)}")

        conn
        |> put_session(:ticket_id, ticket_id)
        |> redirect(to: ~p"/dashboard")

      {:error, reason} ->
        Logger.error("failed to decrypt ticket #{inspect(enc)} because #{inspect(reason)}")

        conn
        |> put_flash(:error, reason)
        |> redirect(to: ~p"/")

      reason ->
        Logger.error("failed to decrypt ticket #{inspect(enc)} because #{inspect(reason)}")

        conn
        |> put_flash(:error, inspect(reason))
        |> redirect(to: ~p"/")
    end
  end

  def reset(conn, _params) do
    Tickets.reset_ticket(conn.assigns.current_ticket)

    conn
    |> redirect(to: ~p"/dashboard")
  end

  def logout(conn, _params) do
    conn
    |> delete_session(:ticket_id)
    |> redirect(to: ~p"/")
  end

  def blank_ticket_form() do
    %{"encrypted_ticket" => nil} |> Phoenix.Component.to_form()
  end
end
