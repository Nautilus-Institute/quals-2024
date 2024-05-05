defmodule GilroyWeb.Miniforum do
  alias Plug.Conn

  alias Gilroy.Tickets

  import Logger, warn: false

  def with_mf_db(conn = %Conn{assigns: %{mf_db: mf_db}}, block) when not is_nil(mf_db) do
    {conn, block.(mf_db)}
  end

  def with_mf_db(
        conn = %Conn{assigns: %{current_ticket: %Tickets.Ticket{id: ticket_id}}},
        block
      ) do
    full_ticket = %Tickets.Ticket{} = Tickets.get_ticket!(ticket_id)
    db = Gilroy.Miniforum.deserialize_or_create(full_ticket)

    Conn.assign(conn, :mf_db, db)
    |> with_mf_db(block)
  end

  @spec update_mf_db(Plug.Conn.t(), (Ticket.t() -> {:ok, map(), any()})) ::
          {Plug.Conn.t(), {any()} | {:error, any()}}
  def update_mf_db(
        conn = %Conn{assigns: %{current_ticket: %Tickets.Ticket{id: ticket_id}}},
        block
      ) do
    result =
      Tickets.with_locked_ticket(ticket_id, fn full_ticket ->
        Logger.debug("starting update_mf_db with_locked_ticket")
        db = Gilroy.Miniforum.deserialize_or_create(full_ticket)
        result = block.(db)
        Logger.debug(result: result)
        {:ok, serialized} = Gilroy.Miniforum.Db.serialize(db)
        params = %{"database" => serialized}
        {:ok, params, result}
      end)

    {conn
     |> Conn.assign(:mf_db, nil), result}
  end
end
