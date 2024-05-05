defmodule GilroyWeb.ForumAuth do
  import Plug.Conn

  use GilroyWeb, :controller

  import GilroyWeb.Miniforum, only: [with_mf_db: 2]
  alias Gilroy.Miniforum.Poster

  import Logger, warn: false

  @spec fetch_conn_poster(Plug.Conn.t(), any()) :: Plug.Conn.t()
  def fetch_conn_poster(conn, _opts) do
    with poster_id <- get_session(conn, :poster_id),
         true <- is_binary(poster_id),
         Logger.info(["poster_id", poster_id]),
         {conn, poster} <- load_poster(conn, poster_id),
         false <- is_nil(poster) do
      Logger.debug("assigning conn poster #{poster.name}")

      conn
      |> assign(:current_poster, poster)
    else
      _other ->
        Logger.debug("no conn poster")

        conn
        |> put_session(:poster_id, nil)
        |> assign(:current_poster, nil)
    end
  end

  def only_unbanned_posters(conn, _opts) do
    maybe_poster = conn.assigns[:current_poster]
    Logger.debug("maybe_poster #{inspect(maybe_poster)}")

    cond do
      maybe_poster && maybe_poster.group == 0 ->
        conn
        |> redirect(to: ~p"/forum/banned.php")
        |> halt()

      maybe_poster ->
        conn

      true ->
        conn
        |> put_flash(:error, "You must be logged in to access this page")
        |> redirect(to: ~p"/forum/index.php")
        |> halt()
    end
  end

  def only_admin_posters(conn, _opts) do
    cond do
      conn.assigns[:current_poster] && conn.assigns[:current_poster].group == 2 ->
        conn

      true ->
        conn
        |> put_flash(:error, "You must be a forum admin to access this page")
        |> redirect(to: ~p"/forum/index.php")
        |> halt()
    end
  end

  defp load_poster(conn, nil) do
    {conn, nil}
  end

  defp load_poster(conn, poster_id) do
    {conn, poster} =
      with_mf_db(conn, fn db ->
        Poster.find(db, poster_id)
      end)
  end

  defp materialize_poster({conn, [poster = %Poster{}]}) do
    {conn, poster}
  end

  defp materialize_poster({conn, _other}) do
    {conn, nil}
  end
end
