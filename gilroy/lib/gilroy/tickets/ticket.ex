defmodule Gilroy.Tickets.Ticket do
  use Ecto.Schema
  import Ecto.Changeset

  @warning_database_size 524_288
  @maximium_database_size 1_048_576

  schema "tickets" do
    field :seed, :integer
    field :db_size, :integer
    field :slug, :string
    field :reset_at, :naive_datetime
    field :database, :binary
    field :serialized, :string

    timestamps(type: :utc_datetime)
  end

  @spec warning_size() :: 524_288
  def warning_size(), do: @warning_database_size
  def maximium_size(), do: @maximium_database_size

  def database_size_state(%__MODULE__{database: db}), do: database_size_state(db)
  def database_size_state(db) when is_binary(db), do: database_size_state(byte_size(db))

  def database_size_state(nil), do: :ok
  def database_size_state(size) when is_integer(size) and size <= @warning_database_size, do: :ok

  def database_size_state(size) when is_integer(size) and size > @maximium_database_size,
    do: :invalid

  def database_size_state(size) when is_integer(size), do: :warning

  def from_ctf_ticket(%CtfTickets.Ticket{
        slug: slug,
        seed: seed,
        serialized: serialized
      }) do
    %Gilroy.Tickets.Ticket{
      slug: slug,
      seed: rem(seed, 9_223_372_036_854_775_807),
      serialized: serialized
    }
  end

  @doc false
  def changeset(ticket, attrs) do
    ticket
    |> cast(attrs, [:slug, :reset_at, :seed, :database])
    |> validate_required([:slug, :seed])
    |> validate_length(:database, max: @maximium_database_size, count: :bytes)
    |> unique_constraint(:slug)
  end
end
