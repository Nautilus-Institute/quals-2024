defmodule Gilroy.Repo do
  use Ecto.Repo,
    otp_app: :gilroy,
    adapter: Ecto.Adapters.Postgres
end
