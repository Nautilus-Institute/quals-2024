defmodule GilroyWeb.Forum.PostController do
  use GilroyWeb, :controller

  import GilroyWeb.Miniforum
  alias Gilroy.Miniforum.Db

  def create(conn, params) do
    with post_params <- merge_post_params(conn, params),
         true <- valid_post(post_params),
         {updated_conn, {:ok, _}} <- make_post(conn, post_params) do
      updated_conn
      |> redirect(to: ~p"/forum/showthread.php?threadid=#{post_params["thread_id"]}")
    else
      _whatever ->
        conn
        |> put_flash(:error, "Failed to reply")
        |> render("new.html", form: form(params), thread_id: params["thread_id"])
    end
  end

  def merge_post_params(conn, params) do
    Map.merge(params, %{"poster_id" => conn.assigns.current_poster.id})
  end

  def valid_post(_params = %{"body" => ""}), do: false
  def valid_post(_params), do: true

  def make_post(conn, post_params) do
    update_mf_db(conn, fn db ->
      Db.ins(
        db,
        """
        INSERT INTO posts
        (thread_id, poster_id, body, posted_at)
        VALUES ($1, $2, $3, $4);
        """,
        [
          post_params["thread_id"],
          post_params["poster_id"],
          post_params["body"],
          DateTime.utc_now()
        ]
      )
    end)
  end

  def form() do
    %{
      "thread_id" => "",
      "body" => ""
    }
    |> Phoenix.Component.to_form()
  end

  def form(params) do
    %{"thread_id" => params["thread_id"], "body" => params["body"]}
    |> Phoenix.Component.to_form()
  end
end
