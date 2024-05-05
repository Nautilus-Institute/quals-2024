defmodule GilroyWeb.Forum.PosterController do
  use GilroyWeb, :controller

  import Logger, warn: false

  import GilroyWeb.Miniforum
  alias Gilroy.Miniforum.Db
  alias Gilroy.Miniforum.Poster

  def show(conn, _params = %{"userid" => id}) do
    {conn, poster_row} =
      with_mf_db(conn, fn db ->
        [poster_row] = Db.get(db, "select * from posters where id = $1 limit 1", [id])
        poster_row
      end)

    poster = %Poster{
      id: Enum.at(poster_row, 0),
      name: Enum.at(poster_row, 1),
      group: Enum.at(poster_row, 3)
    }

    render(conn, "show.html", poster: poster)
  end

  def new(conn, _params) do
    render(conn, "new.html")
  end

  def create(conn, params) do
    with {:ok, passworded_params} <- set_password_digest(params),
         merged_params <- merge_poster_params(passworded_params),
         {updated_conn, {:ok, id}} <- make_poster(conn, merged_params) do
      Logger.debug(["poster_id", id])

      updated_conn
      |> put_session(:poster_id, id)
      |> redirect(to: ~p"/forum/index.php")
    else
      {:error, reason} ->
        conn
        |> put_flash(:error, reason)
        |> render("new.html",
          form: Phoenix.Component.to_form(params)
        )
    end
  end

  @poster_data_types %{
    id: :string,
    name: :string,
    password_digest: :string,
    group: :integer
  }

  defp set_password_digest(
         params = %{
           "password" => pw,
           "password_confirmation" => pw
         }
       ) do
    {:ok,
     params
     |> Map.put("password_digest", Poster.make_password(pw))}
  end

  defp set_password_digest(_params) do
    {:error, "couldn't set password"}
  end

  defp merge_poster_params(params) do
    %{
      "id" => UUID.uuid4(),
      "group" => 1
    }
    |> Map.merge(params)
  end

  defp make_poster(conn, merged_params) do
    try do
      update_mf_db(conn, fn db ->
        wannabe_admin = "2" == merged_params["group"]

        [[admin_count]] =
          Db.get(
            db,
            "SELECT count(id) FROM posters WHERE \"group\" = 2;"
          )

        if wannabe_admin && admin_count > 0 do
          throw({:error, "An admin already exists"})
        end

        {:ok, [[got]]} =
          Db.ins(
            db,
            """
            insert into posters
            (id, name, password_digest, "group")
            values ($1, $2, $3, $4)
            returning id;
            """,
            [
              merged_params["id"],
              merged_params["name"],
              merged_params["password_digest"],
              merged_params["group"]
            ]
          )

        got
      end)
    catch
      {:db_unique, "posters.name"} -> {:error, "name already taken"}
      {:error, mesg} -> {:error, mesg}
    end
  end

  def blank_form() do
    %{
      "name" => "",
      "password" => "",
      "password_confirmation" => "",
      "group" => "1"
    }
    |> Phoenix.Component.to_form()
  end

  @argon2id_opslimit 2
  @argon2id_memlimit 19 * 1024 * 1024

  defp password_create(password) do
    :libsodium_crypto_pwhash_argon2id.str(password)
  end
end
