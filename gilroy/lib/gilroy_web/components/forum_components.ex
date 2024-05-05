defmodule GilroyWeb.ForumComponents do
  use GilroyWeb, :html

  alias Gilroy.Miniforum

  alias Gilroy.Miniforum.Poster

  import Logger, warn: false

  def login_or_signup_form(_assigns = %{current_poster: %Gilroy.Miniforum.Poster{}}), do: ""

  def login_or_signup_form(assigns) do
    ~H"""
    <div class="login_or_signup">
      <.login_form />
      <.signup_form />
    </div>
    """
  end

  def login_form(assigns) do
    assigns =
      assign(assigns,
        form: GilroyWeb.Forum.SessionController.login_form()
      )

    ~H"""
    <div class="login_form">
      <h2>Login</h2>
      <.form for={@form} action={~p"/forum/login.php"}>
        <.input type="text" field={@form["name"]} placeholder="name" label="Username:" />
        <.input type="password" field={@form["password"]} placeholder="password" label="Password:" />
        <.button>Log in</.button>
      </.form>
    </div>
    """
  end

  def signup_form(assigns) do
    assigns =
      assign(assigns,
        form: GilroyWeb.Forum.PosterController.blank_form()
      )

    ~H"""
    <div class="signup_form">
      <h2>Sign Up</h2>
      <.form for={@form} action={~p"/forum/newuser.php"}>
        <.input type="text" field={@form["name"]} placeholder="Username" label="Username:" />
        <.input type="password" field={@form["password"]} placeholder="Password" label="Password:" />
        <.input
          type="password"
          field={@form["password_confirmation"]}
          placeholder="Confirm Password"
          label="Confirm Password:"
        />
        <.button>Create User</.button>
      </.form>
    </div>
    """
  end

  def reply_form(assigns) do
    assigns =
      assign(assigns,
        form: GilroyWeb.Forum.PostController.form()
      )

    ~H"""
    <div class="reply_form">
      <h2>Reply</h2>
      <.form for={@form} action={~p"/forum/newreply.php"} method="post">
        <.input type="hidden" field={@form["thread_id"]} value={@thread_id} />
        <dl>
          <dt>Content</dt>
          <dd><.input type="textarea" field={@form["body"]} placeholder="body" /></dd>
          <dt></dt>
          <dd>
            <.button>Reply</.button>
          </dd>
        </dl>
      </.form>
    </div>
    """
  end

  def thread_header(assigns) do
    ~H"""
    <thead>
      <tr>
        <th class="tag">Tag</th>
        <th class="title">Title</th>
        <th class="poster">Poster</th>
        <th class="postcount">Posts</th>
      </tr>
    </thead>
    """
  end

  def thread_row(assigns = %{thread: thread = %Miniforum.Thread{}}) do
    [op | rest] = thread.posts
    post_count = length(rest)

    assigns =
      assigns
      |> assign(:op, op)
      |> assign(:post_count, post_count)

    ~H"""
    <tr class="thread" id={@thread.id}>
      <td class="tag"><img src={"/images/posticons/#{@thread.tag}"} alt={@thread.tag} /></td>
      <td class="title"><a href={"/forum/#{@thread.id}"}><%= @thread.title %></a></td>
      <td class="poster"><%= @op.poster.name %></td>
      <td class="postcount"><%= @post_count %></td>
    </tr>
    """
  end

  # connascent with GilroyWeb.Forum.ForumController
  def thread_row(
        assigns = %{
          thread: [
            thread_id,
            thread_tag,
            thread_title,
            poster_id,
            poster_name,
            post_count,
            last_posted_at
          ]
        }
      ) do
    assigns =
      assigns
      |> assign(%{
        thread_id: thread_id,
        thread_tag: thread_tag,
        thread_title: thread_title,
        poster_id: poster_id,
        poster_name: poster_name,
        post_count: post_count,
        last_posted_at: last_posted_at
      })

    ~H"""
    <tr class="thread" id={@thread_id}>
      <td class="tag"><img src={"/images/posticons/#{@thread_tag}"} alt={@thread_tag} /></td>
      <td class="title">
        <a href={"/forum/showthread.php?threadid=#{@thread_id}"}><%= @thread_title %></a>
      </td>
      <td class="poster"><%= @poster_name %></td>
      <td class="postcount"><%= @post_count %></td>
    </tr>
    """
  end

  def thread_row(assigns = %{thread: _something_weird}) do
    ~H"""
    <pre><%= inspect(@thread) %></pre>
    """
  end

  def post_row(
        assigns = %{
          post: _post = [post_id, posted_at, body, poster_id, poster_name, poster_group]
        }
      ) do
    assigns =
      assigns
      |> assign(%{
        post_id: post_id,
        posted_at: posted_at,
        body: body,
        poster_id: poster_id,
        poster_name: poster_name,
        poster_group: poster_group,
        poster_group_name: Poster.get_group_name(poster_group)
      })

    ~H"""
    <tr class="post" id={@post_id}>
      <td class={["poster", @poster_group_name]}>
        <strong><%= @poster_name %></strong>
        <br />
        <small><%= @poster_group_name %></small>
      </td>
      <td>
        <p><%= @body %></p>
      </td>
    </tr>
    <tr class="post_meta">
      <td><time><%= @posted_at %></time></td>
      <td>
        <.link href={"/forum/showuser.php?userid=#{@poster_id}"}>
          Profile for <%= @poster_name %>
        </.link>
      </td>
    </tr>
    """
  end

  def thread_tag_picker(%{field: %Phoenix.HTML.FormField{} = field} = assigns) do
    assigns =
      assigns
      |> assign(field: nil, id: field.id)
      |> assign(:errors, Enum.map(field.errors, &translate_error(&1)))
      |> assign_new(:name, fn -> field.name end)

    ~H"""
    <ul class="thread_tag_picker">
      <li :for={tag <- @tags}>
        <label>
          <input type="radio" name={@name} id={@id} value={tag} />
          <img src={"/images/posticons/#{tag}"} alt={tag} />
        </label>
      </li>
    </ul>
    """
  end
end
