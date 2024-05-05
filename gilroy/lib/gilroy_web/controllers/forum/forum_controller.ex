defmodule GilroyWeb.Forum.ForumController do
  use GilroyWeb, :controller

  import Logger, warn: false

  import GilroyWeb.Miniforum
  alias Gilroy.Miniforum.Db

  def index(conn, _params) do
    {conn, {thread_stream, admin_stream}} =
      with_mf_db(conn, fn db ->
        info(
          thread_count: Db.get(db, "select count(id) from threads"),
          poster_count: Db.get(db, "select count(id) from posters"),
          post_count: Db.get(db, "select count(id) from posts")
        )

        thread_stream =
          Db.stream(db, """
          WITH
            post_counts AS
            (select
              thread_id, count(id) as post_count
              from posts
              group by thread_id),
            last_posts AS
            (select
              thread_id, max(posted_at) as last_posted_at
              from posts
              group by thread_id)

          SELECT
            threads.id, threads.tag, threads.title,
            posters.id, posters.name,
            post_counts.post_count, last_posts.last_posted_at
          FROM threads
            JOIN posters ON threads.poster_id = posters.id
            JOIN post_counts ON threads.id = post_counts.thread_id
            JOIN last_posts ON threads.id = last_posts.thread_id
          ORDER BY last_posted_at DESC;
          """)

        admin_stream =
          Db.stream(db, """
          SELECT id, name
          FROM posters
          WHERE "group" = 2
          """)

        {thread_stream, admin_stream}
      end)

    render(conn, "index.html", thread_stream: thread_stream, admin_stream: admin_stream)
  end
end
