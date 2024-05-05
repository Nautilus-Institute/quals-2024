defmodule GilroyWeb.Forum.ThreadController do
  use GilroyWeb, :controller

  import Logger, warn: false

  import GilroyWeb.Miniforum
  alias Gilroy.Miniforum.Db
  alias Gilroy.Miniforum.ThreadTags

  alias Gilroy.Miniforum.Poster

  def show(conn, _params = %{"threadid" => thread_id}) do
    {conn, new_assigns} =
      with_mf_db(conn, fn db ->
        [[thread_title, thread_tag]] =
          Db.get(
            db,
            """
            SELECT title, tag FROM threads WHERE id = $1;
            """,
            [thread_id]
          )

        stream =
          Db.stream(
            db,
            """
            SELECT
              posts.id, posts.posted_at, posts.body,
              posters.id, posters.name, posters."group"
            FROM posts
              JOIN posters ON posts.poster_id = posters.id
            WHERE posts.thread_id = $1
            ORDER BY posts.posted_at;
            """,
            [thread_id]
          )

        %{
          thread_title: thread_title,
          thread_tag: thread_tag,
          thread_id: thread_id,
          post_stream: stream
        }
      end)

    conn
    |> render("show.html", new_assigns)
  end

  def new(conn, _params) do
    render_new(conn)
  end

  defp render_new(conn) do
    render(conn, "new.html",
      form: form(),
      tags: ThreadTags.get_tags(),
      banmes: ThreadTags.get_banme_tags()
    )
  end

  def form() do
    %{
      "title" => "",
      "tag" => "",
      "content" => "",
      "poster_id" => ""
    }
    |> Phoenix.Component.to_form()
  end

  def create(conn, params) do
    with base <- %{
           "id" => UUID.uuid4(),
           "posted_at" => DateTime.utc_now(),
           "poster_id" => conn.assigns.current_poster.id
         },
         thread_params <- merge_thread_params(base, params),
         {updated_conn, {:ok, id}} <- make_thread(conn, thread_params) do
      updated_conn
      |> redirect(to: ~p"/forum/showthread.php?threadid=#{id}")
    else
      _whatever ->
        conn
        |> put_flash(:error, "Failed to create thread")
        |> render_new()
    end
  end

  defp merge_thread_params(base, params) do
    Map.merge(base, params)
  end

  defp make_thread(conn, thread_params) do
    update_mf_db(conn, fn db ->
      Db.ins(
        db,
        """
        INSERT INTO threads (id, title, tag, poster_id, posted_at)
        VALUES ($1, $2, $3, $4, $5);
        """,
        [
          thread_params["id"],
          thread_params["title"],
          thread_params["tag"],
          thread_params["poster_id"],
          thread_params["posted_at"]
        ]
      )

      Db.ins(
        db,
        """
        INSERT INTO posts (id, thread_id, posted_at, body, poster_id)
        VALUES ($1, $2, $3, $4, $5);
        """,
        [
          UUID.uuid4(),
          thread_params["id"],
          thread_params["posted_at"],
          thread_params["content"],
          thread_params["poster_id"]
        ]
      )

      if ThreadTags.is_banme_tag(thread_params["tag"]) do
        Db.upd(
          db,
          """
          UPDATE posters
          SET "group"=$1 WHERE id=$2
          """,
          [
            Poster.get_group_id(:banned),
            thread_params["poster_id"]
          ]
        )
      end

      thread_params["id"]
    end)
  end
end
