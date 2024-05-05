defmodule Gilroy.Miniforum.ThreadTags do
  @moduledoc "enumerates and classifies thread tags from images on disk"

  use Agent

  import Gilroy.Miniforum.Picker, only: [pick: 2]

  require Logger, warn: false

  @type t :: %__MODULE__{
          tags: [String.t()],
          banme_tags: [String.t()]
        }
  defstruct tags: [], banme_tags: []

  # api
  def get_tags() do
    Agent.get(__MODULE__, & &1.tags)
  end

  def get_banme_tags() do
    Agent.get(__MODULE__, & &1.banme_tags)
  end

  def pick_tag(state) do
    pick(state, get_tags())
  end

  def pick_banme_tag(state) do
    pick(state, get_banme_tags())
  end

  def is_banme_tag(tag) do
    Agent.get(__MODULE__, & &1.banme_tags)
    |> Enum.member?(tag)
  end

  def reload() do
    Agent.cast(__MODULE__, &load/1)
  end

  # internal
  @spec start_link(any()) :: {:ok, pid()}
  def start_link(_) do
    {:ok, pid} = Agent.start_link(fn -> %__MODULE__{} end, name: __MODULE__)
    reload()
    {:ok, pid}
  end

  @spec load(Gilroy.Miniforum.ThreadTags.t()) :: any()
  def load(_old_state = %__MODULE__{}) do
    :code.priv_dir(:gilroy)
    |> Path.join("static/images/posticons")
    |> File.ls!()
    |> Enum.filter(fn filename ->
      !Regex.match?(~r/[[:xdigit:]]{32}\.(png|jpg|jpeg|gif)$/, filename)
    end)
    |> Enum.sort()
    |> Enum.reverse()
    |> Enum.reduce(%__MODULE__{}, fn filename, _state = %__MODULE__{tags: ts, banme_tags: bs} ->
      base_tag = String.replace(filename, ~r{\.[a-zA-Z]+}, "")

      bs =
        if String.starts_with?(base_tag, "banme") do
          [filename | bs]
        else
          bs
        end

      %__MODULE__{tags: [filename | ts], banme_tags: bs}
    end)
    |> tap(fn state ->
      Logger.debug("loaded #{length(state.tags)} tags, #{length(state.banme_tags)} banme tags")
    end)
  end
end
