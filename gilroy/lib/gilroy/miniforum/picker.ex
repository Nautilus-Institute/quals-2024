defmodule Gilroy.Miniforum.Picker do
  @spec pick(:rand.state(), list()) ::
          {:rand.state(), any()}
  def pick(state, list) do
    {idx, state} = :rand.uniform_s(length(list), state)
    {state, Enum.at(list, idx - 1)}
  end

  @spec normal(:rand.state(), [[String.t()]], [String.t()], String.t()) ::
          {:rand.state(), String.t()}
  def normal(state, pieces, run \\ [], joiner \\ "")

  def normal(state, [], run, joiner) do
    {state, run |> Enum.reverse() |> Enum.join(joiner)}
  end

  def normal(state, [piece | pieces], run, joiner) do
    {new_state, picked} = pick(state, piece)

    normal(new_state, pieces, [picked | run], joiner)
  end

  # start of legitbs quals 2013 :3
  @datetime_start ~N[2013-06-15 00:00:00]
  @datetime_span_s 10 * 365 * 24 * 60 * 60

  @spec datetime(:rand.state(), NaiveDateTime.t()) :: {:rand.state(), NaiveDateTime.t()}
  def datetime(state, start_time \\ @datetime_start) do
    {diff, state} = :rand.uniform_s(@datetime_span_s, state)

    {state, NaiveDateTime.add(start_time, diff)}
  end
end
