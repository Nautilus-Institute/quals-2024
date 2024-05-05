defmodule GilroyWeb.PageController do
  use GilroyWeb, :controller

  import Logger, warn: false

  import GilroyWeb.TicketsController, only: [blank_ticket_form: 0]

  def home(conn, _params) do
    # The home page is often custom made,
    # so skip the default app layout.
    render(conn, :home,
      ticket_form: blank_ticket_form(),
      page_title: "welcome"
    )
  end

  def thread_tags(conn, params) do
    if params["reload"] == "true" do
      Agent.cast(Gilroy.Miniforum.ThreadTags, &Gilroy.Miniforum.ThreadTags.load/1)
    end

    render(conn, :thread_tags, %{
      tags: Gilroy.Miniforum.ThreadTags.get_tags(),
      banme_tags: Gilroy.Miniforum.ThreadTags.get_banme_tags()
    })
  end

  def dashboard(conn, _params) do
    ticket = conn.assigns[:current_ticket]

    conn
    |> assign(:ticket, ticket)
    |> assign(:page_title, "dashboard")
    |> render(:dashboard)
  end

  def forum(conn, _params) do
    state = :rand.seed_s(:exsss)
    init_state = state

    start_time = :os.system_time(:millisecond)

    {state, forum} = Gilroy.Miniforum.new(state)
    # {:ok, serialized} = Gilroy.Miniforum.create(forum)

    end_time = :os.system_time(:millisecond)

    render(conn, :forum, %{
      init_state: init_state,
      state: state,
      forum: forum,
      # serialized_len: byte_size(serialized),
      time_took: end_time - start_time
    })
  end

  def databass(conn, %{"ticket_id" => ticket_id}) do
    ticket = Gilroy.Tickets.get_ticket!(ticket_id)
    send_download(conn, {:binary, ticket.database}, filename: "ticket-#{ticket_id}.sqlite3")
  end

  def rules(conn, _params) do
    render(conn, "rules.html")
  end

  def banned(conn, _params) do
    render(conn, "banned.html")
  end
end
