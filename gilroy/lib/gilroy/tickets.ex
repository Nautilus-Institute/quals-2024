defmodule Gilroy.Tickets do
  @moduledoc """
  The Tickets context.
  """

  import Logger, warn: false
  import Ecto.Query, warn: false
  alias Gilroy.Repo

  alias Gilroy.Tickets.Ticket

  @doc """
  Returns the list of tickets.

  ## Examples

      iex> list_tickets()
      [%Ticket{}, ...]

  """
  def list_tickets do
    Repo.all(Ticket)
  end

  @doc """
  Gets a single ticket.

  Raises `Ecto.NoResultsError` if the Ticket does not exist.

  ## Examples

      iex> get_ticket!(123)
      %Ticket{}

      iex> get_ticket!(456)
      ** (Ecto.NoResultsError)

  """
  def get_ticket!(id), do: Repo.get!(Ticket, id)

  @spec get_ticket_without_database(any()) :: any()
  def get_ticket_without_database(id) do
    from(t in Ticket, where: t.id == ^id, select: %{t | database: nil})
    |> Repo.one()
  end

  @spec get_ticket_without_database!(any()) :: any()
  def get_ticket_without_database!(id) do
    from(t in Ticket, where: t.id == ^id, select: %{t | database: nil})
    |> Repo.one!()
  end

  def get_ticket_by_slug!(slug), do: Repo.get_by!(Ticket, slug: slug)

  def get_ticket_by_slug_without_database!(slug) do
    from(t in Ticket, where: t.slug == ^slug, select: %{t | database: nil})
    |> Repo.one!()
  end

  @spec with_locked_ticket(String.t(), (Ticket.t() -> {map(), any()})) ::
          {any()} | {:error, any()}
  def with_locked_ticket(ticket_id, block) do
    Repo.transaction(fn ->
      with ticket = %Ticket{} <- try_lock_ticket!(ticket_id),
           {:ok, params, result} <-
             :telemetry.span([:tickets, :with_locked], %{}, fn ->
               {block.(ticket), %{}}
             end),
           {:ok, _updated} <- update_ticket(ticket, params) do
        result
      else
        {:error, reason} ->
          Logger.error([ticket_id: ticket_id],
            error_with_locked_ticket: reason
          )

          {:error, reason}

        other ->
          Logger.error([ticket_id: ticket_id],
            other_with_locked_ticket: other
          )

          {:error, other}
      end
    end)
  end

  defp try_lock_ticket!(ticket_id) do
    from(t in Ticket,
      where: t.id == ^ticket_id,
      lock: "for update skip locked"
    )
    |> Repo.one()
  end

  @doc """
  Creates a ticket.

  ## Examples

      iex> create_ticket(%{field: value})
      {:ok, %Ticket{}}

      iex> create_ticket(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_ticket(attrs \\ %{}) do
    %Ticket{}
    |> Ticket.changeset(attrs)
    |> Repo.insert()
  end

  def upsert_ticket(encrypted_ticket) when is_binary(encrypted_ticket) do
    with ctf_tik = %CtfTickets.Ticket{} <-
           (try do
              CtfTickets.Ticket.deserialize(
                challenge_secret_key(),
                encrypted_ticket
              )
            rescue
              CaseClauseError -> {:error, "couldn't accept ticket"}
            end),
         db_tik <- %Ticket{} = upsert_ticket(ctf_tik) do
      db_tik
    else
      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, other}
    end
  end

  def upsert_ticket(%CtfTickets.Ticket{slug: slug} = ctf_tik) do
    %Ticket{} =
      ctf_tik
      |> Ticket.from_ctf_ticket()
      |> Repo.insert!(on_conflict: :nothing)

    get_ticket_by_slug_without_database!(slug)
  end

  @doc """
  Updates a ticket.

  ## Examples

      iex> update_ticket(ticket, %{field: new_value})
      {:ok, %Ticket{}}

      iex> update_ticket(ticket, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_ticket(%Ticket{} = ticket, attrs) do
    ticket
    |> Ticket.changeset(attrs)
    |> Repo.update()
  end

  def reset_ticket(%Ticket{} = ticket) do
    from(t in Ticket, where: t.id == ^ticket.id)
    |> Repo.update_all(set: [database: nil, reset_at: DateTime.utc_now()])
  end

  @doc """
  Deletes a ticket.

  ## Examples

      iex> delete_ticket(ticket)
      {:ok, %Ticket{}}

      iex> delete_ticket(ticket)
      {:error, %Ecto.Changeset{}}

  """
  def delete_ticket(%Ticket{} = ticket) do
    Repo.delete(ticket)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking ticket changes.

  ## Examples

      iex> change_ticket(ticket)
      %Ecto.Changeset{data: %Ticket{}}

  """
  def change_ticket(%Ticket{} = ticket, attrs \\ %{}) do
    Ticket.changeset(ticket, attrs)
  end

  def to_flag(%Ticket{serialized: serialized} = ticket, ip_address) do
    ct =
      CtfTickets.Ticket.deserialize(
        challenge_secret_key(),
        serialized
      )

    rc = CtfTickets.Receipt.initialize(challenge_secret_key(), ct, ip_address)

    CtfTickets.Receipt.serialize(rc)
  end

  defp challenge_secret_key do
    Application.get_env(:gilroy, Gilroy.Tickets)[:challenge_secret_key]
  end
end
