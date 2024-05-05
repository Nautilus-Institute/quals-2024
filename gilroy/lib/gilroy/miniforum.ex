defmodule Gilroy.Miniforum do
  @moduledoc "per-ticket database, as forum software"

  alias Exqlite.Sqlite3

  alias Gilroy.Miniforum.Db
  alias Gilroy.Miniforum.Post
  alias Gilroy.Miniforum.Poster
  alias Gilroy.Miniforum.Thread
  alias Gilroy.Miniforum.ThreadTags

  alias Gilroy.Tickets
  alias Gilroy.Tickets.Ticket

  require Logger, warn: false

  @type t :: %__MODULE__{
          posters: [Poster],
          threads: [Thread],
          posts: [Post]
        }

  defstruct posters: [], threads: [], posts: []

  @spec deserialize_or_create(%Gilroy.Tickets.Ticket{
          :database => nil | binary()
        }) :: reference()
  def deserialize_or_create(ticket = %Ticket{database: <<>>}), do: definitely_create(ticket)
  def deserialize_or_create(ticket = %Ticket{database: nil}), do: definitely_create(ticket)

  def deserialize_or_create(ticket = %Ticket{database: blob}) when is_binary(blob) do
    with {:ok, db} <- Sqlite3.open(":memory:"),
         :ok <- instrumented_deserialize(db, blob) do
      Logger.info("did deserialize #{byte_size(blob)}")
      db
    else
      _other -> definitely_create(ticket)
    end
  end

  defp instrumented_deserialize(db, blob) do
    :telemetry.span([:miniforum, :deserialize], %{}, fn ->
      got = Sqlite3.deserialize(db, blob)
      {got, %{}}
    end)
  end

  defp definitely_create(ticket = %Ticket{seed: seed}) do
    import Bitwise

    seed = :rand.seed_s(:exsss, [seed >>> 32, seed &&& 0xFFFFFFFF])
    {_state, mf} = new(seed)
    db = create(mf)
    {:ok, ser} = Db.serialize(db)

    {:ok, _updated_ticket} =
      Tickets.update_ticket(ticket, %{database: ser, reset_at: NaiveDateTime.utc_now()})

    with {:ok, db} <- Sqlite3.open(":memory:"),
         :ok <- Sqlite3.deserialize(db, ser) do
      db
    end
  end

  @spec new() :: {:rand.state(), __MODULE__.t()}
  def new() do
    new(:rand.seed_s(:exsss))
  end

  @spec new(:rand.state()) :: {:rand.state(), __MODULE__.t()}
  def new(state) do
    :telemetry.span([:miniforum, :generate], %{}, fn ->
      {state, posters} = make_posters(state)
      {state, threads} = make_threads(state, posters)

      posters = process_banmes(posters, threads)

      posts = Enum.flat_map(threads, & &1.posts)

      {{state, %__MODULE__{posters: posters, threads: threads, posts: posts}}, %{}}
    end)
  end

  defp process_banmes(posters, threads) do
    banme_threads =
      threads
      |> Enum.filter(&ThreadTags.is_banme_tag(&1.tag))

    banme_posters = banme_threads |> Enum.map(&(&1.posts |> hd())) |> Enum.map(& &1.poster)

    posters
    |> Enum.map(fn poster ->
      if Enum.member?(banme_posters, poster) do
        %Poster{poster | group: 0}
      else
        poster
      end
    end)
  end

  def create(forum) do
    {:ok, db} = Db.create()

    Db.transact(db, fn ->
      Poster.create(db)
      Thread.create(db)
      Post.create(db)

      Enum.each(forum.posters, &Poster.insert(db, &1))
      Enum.each(forum.threads, &Thread.insert(db, &1))
      Enum.each(forum.posts, &Post.insert(db, &1))
    end)

    db
  end

  defp make_posters(state) do
    {posters, state} =
      1..39
      |> Enum.reduce({[], state}, fn _i, {run, state} ->
        {state, poster} = Poster.new(state)
        {[poster | run], state}
      end)

    {state, admin} = Poster.new(state)
    admin = %Poster{admin | group: 2}

    {state, [admin | posters]}
  end

  defp make_threads(state, posters) do
    {threads, state} =
      1..200
      |> Enum.reduce({[], state}, fn _i, {run, state} ->
        {state, thread} = Thread.new(state, posters)
        {[thread | run], state}
      end)

    {state, threads}
  end
end
