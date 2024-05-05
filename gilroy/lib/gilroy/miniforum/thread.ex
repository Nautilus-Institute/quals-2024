defmodule Gilroy.Miniforum.Thread do
  @moduledoc "a list of posts"

  import Gilroy.Miniforum.Db
  import Gilroy.Miniforum.Picker

  alias Gilroy.Miniforum.ThreadTags

  @type t :: %__MODULE__{
          id: String.t(),
          title: String.t(),
          tag: String.t(),
          posts: [Gilroy.Miniforum.Post.t()],
          poster: Gilroy.Miniforum.Poster.t(),
          posted_at: NaiveDateTime.t()
        }

  defstruct id: nil, title: nil, tag: nil, posts: [], poster: nil, posted_at: nil

  def create(db) do
    :ok =
      exec(
        db,
        "CREATE TABLE threads (
      id VARCHAR PRIMARY KEY,
      title VARCHAR NOT NULL,
      tag VARCHAR NOT NULL,
      poster_id VARCHAR
        NOT NULL
        REFERENCES posters(id),
      posted_at DATETIME NOT NULL
    );"
      )
  end

  @spec new(:rand.state(), [Gilroy.Miniforum.Poster.t()]) :: {:rand.state(), __MODULE__.t()}
  def new(state, posters) do
    {state, title} = make_title(state, posters)
    {state, id} = UUID.uuid4_seeded(state)
    {state, posted} = datetime(state)
    {state, posts} = make_posts(state, id, posters)
    sorted_posts = Enum.sort_by(posts, & &1.posted_at)
    op = sorted_posts |> hd()
    poster = op.poster

    {state, tag} =
      if poster.group != 2 do
        make_any_tag(state)
      else
        ThreadTags.pick_tag(state)
      end

    {state, %__MODULE__{id: id, title: title, tag: tag, posts: sorted_posts, posted_at: posted}}
  end

  @spec new(String.t(), String.t(), String.t(), Gilroy.Miniforum.Poster.t(), NaiveDateTime.t()) ::
          __MODULE__.t() | {:error, String.t()}
  def new(
        _title,
        _tag,
        _content,
        _poster = %Gilroy.Miniforum.Poster{group: 0},
        _posted_at = %NaiveDateTime{}
      ) do
    {:error, "banned"}
  end

  def new(title, tag, content, poster = %Gilroy.Miniforum.Poster{}, posted_at = %NaiveDateTime{}) do
    op = %Gilroy.Miniforum.Post{body: content, poster: poster, posted_at: posted_at}

    %__MODULE__{id: UUID.uuid4(), title: title, tag: tag, posts: [op], posted_at: posted_at}
  end

  def insert(db, thread) do
    op = thread.posts |> hd()

    ins(
      db,
      "INSERT INTO threads (id, title, tag, poster_id, posted_at)
      VALUES (?, ?, ?, ?, ?);",
      [
        thread.id,
        thread.title,
        thread.tag,
        op.poster.id,
        thread.posted_at
      ]
    )
  end

  @spec make_title(:rand.state(), [Gilroy.Miniforum.Poster.t()]) ::
          {:rand.state(), String.t()}
  def make_title(state, posters) do
    {n, state} = :rand.uniform_s(state)

    cond do
      n > 0.9 -> code_help(state)
      n > 0.8 -> predict(state)
      n > 0.7 -> wishlist(state)
      n > 0.6 -> we_do(state)
      n > 0.5 -> callout(state, posters)
      true -> brand(state)
    end
  end

  @spec make_any_tag(:rand.state()) :: {:rand.state(), String.t()}
  def make_any_tag(state) do
    case :rand.uniform_s(state) do
      {n, state} when n > 0.99 ->
        ThreadTags.pick_banme_tag(state)

      {_, state} ->
        ThreadTags.pick_tag(state)
    end
  end

  @spec make_posts(:rand.state(), String.t(), [Gilroy.Miniforum.Poster.t()]) ::
          {:rand.state(), [Gilroy.Miniforum.Post.t()]}
  def make_posts(state, id, posters) do
    {post_factor, state} = :rand.uniform_s(state)
    post_count = (-70 / (21.9 * post_factor - 23) - 2) |> round()

    {posts, state} =
      Enum.reduce(1..post_count, {[], state}, fn _i, {posts, state} ->
        {state, post} = Gilroy.Miniforum.Post.new(state, id, posters)
        {[post | posts], state}
      end)

    {state, posts}
  end

  @code_help_intro [
    "help with",
    "i need help with",
    "how do i",
    "can you even",
    "can you",
    "how do you"
  ]
  @code_help_verb ~w{write implement build code program}
  @code_help_task [
    "a sql join",
    "a web page",
    "a hit counter",
    "a web scraper",
    "a web crawler",
    "a web server",
    "ai-assisted art theft",
    "ai-assisted bias laundering"
  ]
  @code_help_language ~w{python ruby javascript c c++ c# java rust haskell php elixir erlang sql golang swift kotlin typescript}
  @code_help_framework ~w{rails django flask sinatra express spring chatcbt}

  defp code_help(state) do
    normal(
      state,
      [
        @code_help_intro,
        @code_help_verb,
        @code_help_task,
        ["in"],
        @code_help_language,
        @code_help_framework
      ],
      [],
      " "
    )
  end

  @predict_topics ~w{tech computer posting car camera dog cat cooking food coffee flipflop shoe fashion furniture architecture}
  @predict_intervals ~w{seconds minutes hours days weeks months years decades centuries millennia willennia eons}
  defp predict(state) do
    {n, state} = :rand.uniform_s(1000, state)

    normal(
      state,
      [@predict_topics, ["predictions for the next"], [Integer.to_string(n)], @predict_intervals],
      [],
      " "
    )
  end

  @wishlist_wants ~w{wishlist desires craves needs wants gripes}
  defp wishlist(state) do
    normal(state, [@predict_topics, @wishlist_wants], [], " ")
  end

  @we_do_intro [
    "does anyone else",
    "dae",
    "anyone else",
    "can i",
    "why do you",
    "why do we",
    "why does everyone",
    "why do we all",
    "can we not"
  ]
  @we_do_verb ~w{eat drink drive smoke vape play watch listen}
  @we_do_thing ~w{food alcohol weed cigarettes vapes games movies music cars bikes}

  defp we_do(state) do
    normal(state, [@we_do_intro, @we_do_verb, @we_do_thing, ["?"]], [], " ")
  end

  @brand_name ~w{cinco glorbo hooli initech wernhamhogg penetrobe genco veridian yunoboco takoroka tentatek zekko zink forge inkline cuttlegear krak-on rockenberg skalop princess-swish tomorrow waystar-royco cogswell-cogs stanley-sprockets }
  @brand_thread [
    "appreciation thread",
    "sucks",
    "did a thing",
    "is the best",
    "is the worst",
    "is steadily getting worse",
    "is annoying",
    "annoys me",
    "pissed me off for the last time",
    "failed me"
  ]
  defp brand(state) do
    normal(state, [@brand_name, @brand_thread], [], " ")
  end

  @callouts [
    "makes me mad",
    "is annoying",
    "rocks",
    "has bad taste",
    "sent me a package",
    "sent me this disk",
    "sent me a cd",
    "made a thing",
    "wrote me a song",
    "wrote me a poem",
    "epic fail"
  ]
  defp callout(state, posters) do
    {state, poster} = pick(state, posters)
    normal(state, [[poster.name], @callouts], [], " ")
  end
end
