defmodule Gilroy.Miniforum.Db do
  @moduledoc "database tools"

  require Logger, warn: false

  alias Exqlite.Sqlite3

  @size_warning 524_288
  @size_limit 1_048_576

  @type reason() :: atom() | String.t()

  @spec create() :: {:ok, Sqlite3.db()}
  def create() do
    {:ok, db} = Sqlite3.open(":memory:")
    {:ok, db}
  end

  @spec serialize(Sqlite3.db()) :: {:error, reason()} | {:ok, binary()}
  def serialize(db) do
    :telemetry.span([:miniforum, :serialize], %{}, fn ->
      {inner_serialize(db), %{}}
    end)
  end

  defp inner_serialize(db) do
    with {:ok, serialized} <- Sqlite3.serialize(db),
         :ok <- Sqlite3.close(db),
         :ok <- within_size_limit(serialized) do
      :telemetry.execute([:miniforum, :serialize], %{size: byte_size(serialized)})
      {:ok, serialized}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec within_size_warning(binary()) :: :ok | {:warning, reason()}
  def within_size_warning(ser) when byte_size(ser) <= @size_warning, do: :ok

  def within_size_warning(_ser),
    do: {:warning, "database near size limit, consider resetting it"}

  @spec within_size_limit(binary()) :: :ok | {:error, reason()}
  def within_size_limit(ser) when byte_size(ser) <= @size_limit, do: :ok
  def within_size_limit(_ser), do: {:error, "database over size limit"}

  def transact(db, fun) do
    :ok = Sqlite3.execute(db, "BEGIN TRANSACTION;")
    result = fun.()
    :ok = Sqlite3.execute(db, "COMMIT TRANSACTION;")
    result
  end

  @spec exec(Sqlite3.db(), String.t()) :: :ok | {:error, reason()}
  def exec(db, sql) do
    Logger.debug(op: "exec", sql: sql)
    Sqlite3.execute(db, sql)
  end

  @spec prep(Sqlite3.db(), String.t()) :: {:ok, Sqlite3.statement()} | {:error, reason()}
  def prep(db, sql) do
    Logger.debug(op: "prep", sql: sql)
    Sqlite3.prepare(db, sql)
  end

  @spec ins(Sqlite3.db(), String.t(), [any()]) :: {:error, reason()} | {:ok, any()}
  def ins(db, sql, binds) do
    Logger.debug(op: "insert", sql: sql, binds: binds)

    with {:ok, stmt} <- prep(db, sql),
         :ok <- Sqlite3.bind(db, stmt, binds),
         {:ok, id} <- step(db, stmt) do
      Logger.debug(op: "did_insert")
      {:ok, id}
    else
      {:error, reason} ->
        Logger.error(reason: reason)
        {:error, reason}
    end
  end

  def upd(db, sql, binds) do
    Logger.debug(op: "update", sql: sql, binds: binds)

    with {:ok, stmt} <- prep(db, sql),
         :ok <- Sqlite3.bind(db, stmt, binds),
         {:ok, id} <- step(db, stmt) do
      Logger.debug(op: "did_update")
      {:ok, id}
    else
      {:error, reason} ->
        Logger.error(reason: reason)
        {:error, reason}
    end
  end

  def get(db, sql) do
    {:ok, stmt} = prep(db, sql)
    {:ok, rows} = step(db, stmt)
    rows
  end

  def get(db, sql, binds) do
    {:ok, stmt} = prep(db, sql)
    :ok = Sqlite3.bind(db, stmt, binds)
    {:ok, rows} = step(db, stmt)
    rows
  end

  def stream(db, sql) do
    Stream.resource(
      fn ->
        {:ok, stmt} = prep(db, sql)
        stmt
      end,
      fn stmt -> stream_step(db, stmt, sql) end,
      fn stmt -> Sqlite3.release(db, stmt) end
    )
  end

  def stream(db, sql, binds) do
    Stream.resource(
      fn ->
        {:ok, stmt} = prep(db, sql)
        :ok = Sqlite3.bind(db, stmt, binds)
        stmt
      end,
      fn stmt -> stream_step(db, stmt, sql) end,
      fn stmt -> Sqlite3.release(db, stmt) end
    )
  end

  defp stream_step(db, stmt, sql) do
    case Sqlite3.step(db, stmt) do
      :done ->
        {:halt, stmt}

      {:error, reason} ->
        Logger.error(sql: sql, reason: reason)
        {:halt, stmt}

      :busy ->
        stream_step(db, stmt, sql)

      {:row, row} ->
        Logger.debug(row: row)
        {[row], stmt}
    end
  end

  @spec step(Sqlite3.db(), Sqlite3.statement()) :: {:error, reason()} | {:ok, [any()]}
  defp step(db, stmt) do
    :telemetry.span([:miniforum, :step], %{}, fn ->
      {:ok, rows, count} = step(db, stmt, [], 0)
      :telemetry.execute([:miniforum, :step], %{count: count})
      {{:ok, rows}, %{}}
    end)
  end

  defp step(db, stmt, rows, count) do
    case Sqlite3.step(db, stmt) do
      :done ->
        :ok = Sqlite3.release(db, stmt)
        {:ok, rows |> Enum.reverse(), count}

      {:error, reason} ->
        _idk = Sqlite3.release(db, stmt)

        cond do
          got = Regex.run(~r/^UNIQUE constraint failed:\s+(.+)$/, reason) ->
            [_whole, cols] = got
            throw({:db_unique, cols})

          true ->
            {:error, reason}
        end

      :busy ->
        step(db, stmt, rows, count + 1)

      {:row, row} ->
        step(db, stmt, [row | rows], count + 1)
    end
  end
end
