defmodule GilroyWeb.Forum.SessionController do
  use GilroyWeb, :controller

  alias GilroyWeb.ForumAuth
  alias Gilroy.Miniforum.Poster

  import GilroyWeb.Miniforum, only: [with_mf_db: 2]
  import Plug.Conn
  import Logger, warn: false

  def login(conn, %{"name" => name, "password" => password}) do
    {conn, maybe_poster} =
      with_mf_db(conn, fn db ->
        Poster.authenticate(db, name, password)
      end)

    case maybe_poster do
      nil ->
        conn
        |> put_flash(:error, "Invalid name or password")

      poster ->
        conn
        |> put_session(:poster_id, poster.id)
    end
    |> redirect(to: "/forum/index.php")
  end

  def logout(conn, _params) do
    conn
    |> put_session(:poster_id, nil)
    |> redirect(to: "/forum/index.php")
  end

  def login_form do
    %{
      "name" => "",
      "password" => ""
    }
    |> Phoenix.Component.to_form()
  end
end
