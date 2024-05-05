defmodule Gilroy.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      GilroyWeb.Telemetry,
      Gilroy.Repo,
      {DNSCluster, query: Application.get_env(:gilroy, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Gilroy.PubSub},
      # Start a worker by calling: Gilroy.Worker.start_link(arg)
      # {Gilroy.Worker, arg},
      Gilroy.Miniforum.ThreadTags,
      # Start to serve requests, typically the last entry
      GilroyWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Gilroy.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    GilroyWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
