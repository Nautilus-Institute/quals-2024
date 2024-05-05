defmodule Gilroy.Repo.Migrations.CreateTickets do
  use Ecto.Migration

  def change do
    create table(:tickets) do
      add :slug, :string
      add :reset_at, :naive_datetime
      add :seed, :bigint
      add :database, :binary
      add :serialized, :string
      # add :db_size, :integer, generated: "ALWAYS AS (octet_length(database)) STORED"

      timestamps(type: :utc_datetime)
    end

    execute "alter table tickets add column db_size integer generated always as (octet_length(database)) stored;"

    create unique_index(:tickets, [:slug])
  end
end
