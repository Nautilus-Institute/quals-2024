defmodule GilroyWeb.Router do
  use GilroyWeb, :router

  import GilroyWeb.TicketAuth
  import GilroyWeb.ForumAuth

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {GilroyWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_conn_ticket
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  defp admin_auth_plug(conn, _opts) do
    Plug.BasicAuth.basic_auth(
      conn,
      Application.get_env(:gilroy, :basic_auth)
    )
    |> put_layout(html: {GilroyWeb.Layouts, :admin_app})
  end

  pipeline :admin_auth do
    plug :admin_auth_plug
  end

  scope "/", GilroyWeb do
    pipe_through [:browser]

    get "/rules", PageController, :rules
  end

  scope "/", GilroyWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get "/", PageController, :home

    post "/tickets", TicketsController, :create
  end

  scope "/", GilroyWeb do
    pipe_through [:browser, :redirect_unless_user_is_authenticated]

    get "/dashboard", PageController, :dashboard
    delete "/reset", TicketsController, :reset
    delete "/logout", TicketsController, :logout
  end

  scope "/forum", GilroyWeb do
    pipe_through [:browser, :redirect_unless_user_is_authenticated, :fetch_conn_poster]

    get "/", Forum.ForumController, :index

    get "/index.php", Forum.ForumController, :index
    get "/showforum.php", Forum.ForumController, :index

    get "/signup.php", Forum.PosterController, :create
    post "/signup.php", Forum.PosterController, :new_form

    get "/showuser.php", Forum.PosterController, :show
    get "/newuser.php", Forum.PosterController, :new
    post "/newuser.php", Forum.PosterController, :create

    post "/login.php", Forum.SessionController, :login
    delete "/logout.php", Forum.SessionController, :logout

    get "/rules.php", PageController, :rules
  end

  # land of the living
  scope "/forum", GilroyWeb do
    pipe_through [
      :browser,
      :redirect_unless_user_is_authenticated,
      :fetch_conn_poster,
      :only_unbanned_posters
    ]

    get "/showthread.php", Forum.ThreadController, :show
    get "/newthread.php", Forum.ThreadController, :new
    post "/newthread.php", Forum.ThreadController, :create

    get "/newreply.php", Forum.PostController, :new
    post "/newreply.php", Forum.PostController, :create
  end

  scope "/forum", GilroyWeb do
    pipe_through [
      :browser,
      :redirect_unless_user_is_authenticated,
      :fetch_conn_poster,
      :only_admin_posters
    ]

    get "/admin.php", Forum.AdminController, :index
  end

  scope "/admin", GilroyWeb, assigns: %{current_ticket: nil} do
    pipe_through [:browser, :admin_auth]

    live_session(:ticket_admin, layout: {GilroyWeb.Layouts, :admin_app}) do
      live "/tickets", TicketLive.Index, :index

      live "/tickets/:id", TicketLive.Show, :show
    end

    get "/thread_tags", PageController, :thread_tags
    get "/forum", PageController, :forum

    get "/databass/:ticket_id", PageController, :databass

    import Phoenix.LiveDashboard.Router

    live_dashboard "/dashboard", metrics: GilroyWeb.Telemetry
  end

  # Other scopes may use custom stacks.
  # scope "/api", GilroyWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard in development
  if Application.compile_env(:gilroy, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).

    scope "/dev" do
      pipe_through :browser
    end
  end
end
