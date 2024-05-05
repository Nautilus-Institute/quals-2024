defmodule Gilroy.Miniforum.Post do
  @moduledoc "a post in a thread"

  import Gilroy.Miniforum.Db
  import Gilroy.Miniforum.Picker

  @type t :: %__MODULE__{
          id: String.t(),
          thread_id: String.t(),
          poster: Gilroy.Miniforum.Poster.t(),
          body: String.t(),
          posted_at: NaiveDateTime.t()
        }
  defstruct id: nil, thread_id: nil, poster: nil, body: nil, posted_at: nil

  def create(db) do
    :ok =
      exec(
        db,
        "CREATE TABLE posts (
      id VARCHAR PRIMARY KEY,
      thread_id VARCHAR
        NOT NULL
        REFERENCES threads(id),
      poster_id VARCHAR
        NOT NULL
        REFERENCES posters(id),
      body VARCHAR NOT NULL,
      posted_at DATETIME NOT NULL
    );"
      )
  end

  @spec new(:rand.state(), String.t(), [Gilroy.Miniforum.Poster.t()]) ::
          {:rand.state(), __MODULE__.t()}
  def new(state, thread_id, posters) when is_binary(thread_id) and is_list(posters) do
    {state, id} = UUID.uuid4_seeded(state)
    {state, poster} = pick(state, posters)
    body = "beef"
    {state, posted} = datetime(state)

    {state,
     %__MODULE__{id: id, thread_id: thread_id, poster: poster, body: body, posted_at: posted}}
  end

  @spec new(String.t(), Gilroy.Miniforum.Poster.t(), NaiveDateTime.t()) ::
          __MODULE__.t() | {:error, String.t()}
  def new(_body, _poster = %Gilroy.Miniforum.Poster{group: 0}, _posted_at = %NaiveDateTime{}) do
    {:error, "banned"}
  end

  def new(body, poster = %Gilroy.Miniforum.Poster{}, posted_at = %NaiveDateTime{}) do
    %__MODULE__{id: UUID.uuid4(), body: body, poster: poster, posted_at: posted_at}
  end

  def insert(db, post) do
    ins(
      db,
      "INSERT INTO posts (id, thread_id, poster_id, body, posted_at)
        VALUES (?, ?, ?, ?, ?);",
      [post.id, post.thread_id, post.poster.id, post.body, post.posted_at]
    )
  end
end
