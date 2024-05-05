defmodule Gilroy.Miniforum.Poster do
  @moduledoc "a poster"

  require Logger, warn: false

  import Gilroy.Miniforum.Db
  import Gilroy.Miniforum.Picker

  @type t :: %__MODULE__{
          id: String.t(),
          name: String.t(),
          password_digest: String.t(),
          group: integer()
        }

  defstruct id: nil,
            name: nil,
            password_digest: nil,
            group: 0

  @group_name_to_id %{
    :banned => 0,
    :normal => 1,
    :admin => 2
  }

  @id_to_group_name %{
    0 => :banned,
    1 => :normal,
    2 => :admin
  }

  def get_group_id(group_name) do
    @group_name_to_id[group_name]
  end

  def get_group_name(group_id) do
    @id_to_group_name[group_id]
  end

  def create(db) do
    :ok =
      exec(
        db,
        "CREATE TABLE posters (
      id VARCHAR PRIMARY KEY,
      name VARCHAR
        NOT NULL
        UNIQUE,
      password_digest VARCHAR NOT NULL,
      \"group\" INTEGER
        NOT NULL
    );"
      )

    :ok =
      exec(
        db,
        "CREATE INDEX poster_group_idx ON posters (\"group\");"
      )
  end

  @spec new(:rand.state()) :: {:rand.state(), __MODULE__.t()}
  def new(state) do
    {state, name} = make_name(state)
    {state, id} = UUID.uuid4_seeded(state)

    {state,
     %__MODULE__{id: id, name: name, password_digest: "x", group: @group_name_to_id[:normal]}}
  end

  def find(db, poster_id) do
    get(db, "SELECT id, name, password_digest, \"group\"
      FROM posters
      WHERE id = ?;", [poster_id])
    |> materialize()
  end

  def authenticate(db, name, password) do
    get(db, "SELECT id, name, password_digest, \"group\"
      FROM posters
      WHERE name = ?;", [name])
    |> materialize()
    |> check_password(password)
  end

  defp materialize([_poster_row = [id, name, digest, group]]) do
    %__MODULE__{
      id: id,
      name: name,
      password_digest: digest,
      group: group
    }
  end

  defp materialize(other), do: nil

  @asd_password "$argon2id$v=19$m=12288,t=3,p=1$l59k2/NVP8TKf+jd0qbBxQ$Wg2Onc+3pO9xqfmj3jwK5+3q0UVT2zMW+6Z6zQUh1Tw"
  defp check_password(nil, _password) do
    :libsodium_crypto_pwhash_argon2id.str_verify(@asd_password, "nope")
    nil
  end

  defp check_password(poster = %__MODULE__{password_digest: digest}, password) do
    case :libsodium_crypto_pwhash_argon2id.str_verify(digest, password) do
      0 -> poster
      _other -> nil
    end
  end

  @spec new(String.t(), String.t(), integer()) :: Gilroy.Miniforum.Poster.t()
  @spec new(binary(), binary()) :: Gilroy.Miniforum.Poster.t()
  def new(name, password, group_id \\ 1) do
    %__MODULE__{
      id: UUID.uuid4(),
      name: name,
      password_digest: password |> make_password(),
      group: group_id
    }
  end

  def insert(db, poster) do
    ins(db, "INSERT INTO posters (id, name, password_digest, \"group\")
            VALUES (?, ?, ?, ?) RETURNING id;", [
      poster.id,
      poster.name,
      poster.password_digest,
      poster.group
    ])
  end

  @ops_limit 3
  @mem_limit 12 * 1024 * 1024

  def make_password(password) do
    :libsodium_crypto_pwhash_argon2id.str(password, @ops_limit, @mem_limit)
  end

  @spec make_name(
          {%{
             :next => (any() -> {any(), any()}),
             :type => atom(),
             optional(:bits) => non_neg_integer(),
             optional(:jump) => ({any(), any()} -> {any(), any()}),
             optional(:max) => non_neg_integer(),
             optional(:uniform) => ({any(), any()} -> {any(), any()}),
             optional(:uniform_n) => (pos_integer(), {any(), any()} -> {any(), any()}),
             optional(:weak_low_bits) => non_neg_integer()
           }, any()}
        ) ::
          {{%{
              :next => (any() -> any()),
              :type => atom(),
              optional(:bits) => non_neg_integer(),
              optional(:jump) => (any() -> any()),
              optional(:max) => non_neg_integer(),
              optional(:uniform) => (any() -> any()),
              optional(:uniform_n) => (any(), any() -> any()),
              optional(:weak_low_bits) => non_neg_integer()
            }, any()}, binary()}
  def make_name(state) do
    {n, state} = :rand.uniform_s(state)

    {state, base} = cond do
      n > 0.9999 -> taargus(state)
      n > 0.999 -> yospos(state)
      n > 0.95 -> nauty(state)
      n > 0.9 -> counterstrike(state)
      n > 0.8 -> splatoon(state)
      n > 0.7 -> twitter_egg(state)
      n > 0.6 -> food(state)
      n > 0.5 -> family_guy(state)
      n > 0.4 -> simpsons(state)
      n > 0.35 -> vape_guy(state)
      n > 0.25 -> e1(state)
      n > 0.2 -> juggalo(state)
      n > 0.1 -> cat(state)
      true -> brand(state)
    end

    {numbers, state} = :rand.uniform_s(100_000, state)
    more = [base, numbers |> Integer.to_string()]
      |> Enum.join("")

    {state, more}
  end

  defp taargus(state) do
    {state, "taargüs taargüs"}
  end

  @nauty_names ~w{vito tommy fish itszn thing2 hj nafod mike_pizza jay anton}
  defp nauty(state) do
    normal(state, [@nauty_names])
  end

  @yospos_names ~w{stumps fat shaggar faxlore hex userdeath panacea progressivejpeg switchwitch skeletron bonzoesc karms lovecorecreatrix mcdram bhodi gar gonadicio blobert pardot mononcqc lutha ultraklystron scope mindset arcon wigglywaynedds prognar phone }
  defp yospos(state) do
    normal(state, [@yospos_names])
  end

  @joiner ["-", "_", "+", "_xXx_", " ", "~"]

  @splatoon_adjective ~w{wet gold deep dry fresh hot spicy damp front turqoise chirpy super zap superfresh}
  @splatoon_character ~w{callie marie cuttlefish pearl marina captain shiver frye bigman agent3 agent4 smallfry octavio cqcumber acht judd liljudd mrgrizz isopadre orca sheldon annie moe jelonzo crustysean spyke flow craymond jelfonzo bisk murch gnarlyeddy nails jellafleur mrcoco harmony marigold shelly donny fredcrumbs tartar beika kikura uotora nami ichiya 004clm murasaki yoko}
  @splatoon_fan ~w{fan lover stan fanboy fangirl fiend defender champion king queen ruler }

  defp splatoon(state) do
    normal(state, [@splatoon_adjective, @splatoon_character, @splatoon_fan], [], " ")
  end

  @open_phoneme ~w{ch gr pl st sh sm w l sl gl g v b bl vl cl kl tr th j}
  @vowel ~w{a e i o u ou eu ue au}
  @close_phoneme ~w{k c p g b t }

  defp counterstrike(state) do
    normal(state, [@open_phoneme, @vowel, @close_phoneme])
  end

  @geezer_name ~w{walter randall gerald greggg dorkus glenda blenda santana jebediah grape prudence boof susan bonnie clyde garrry truck justice noice davidiah boofus brandt bront}

  defp twitter_egg(state) do
    {numbers, state} = :rand.uniform_s(100_000, state)
    normal(state, [@geezer_name, @geezer_name, [numbers |> Integer.to_string()]])
  end

  @food_adjective ~w{spicy sweet sour salty bitter umami fried baked grilled roasted steamed boiled raw }
  @food_noun ~w{chicken beef pork fish tofu tempeh eggplant mushroom noodle rice salad sandwich soup stew curry man seafood spider crab lobster gumbo jambalaya paella ragout ragu ratatouille spaghetti lasagna pizza burger taco burrito sushi sashimi steak}

  defp food(state) do
    normal(state, [@food_adjective, @joiner, @food_noun])
  end

  @family_guy_character ~w{stewie peter lois meg chris brian quagmire joe cleveland clevelandjr herbert adam west carter tom tucker mort goldman neil goldman angela consuela bruce jasper james woods jillian barbara pewterschmidt vinny}
  defp family_guy(state) do
    {numbers, state} = :rand.uniform_s(100_000, state)
    normal(state, [@family_guy_character, @joiner, [numbers |> Integer.to_string()]])
  end

  @simpsons_character ~w{bart lisa maggie homer marge abe moe barney krusty flanders milhouse nelson ralph wiggum skinner burns smithers apu comicbookguy groundskeeperwillie otto drnick drhibbert drhomer drfrink drjul}
  defp simpsons(state) do
    {numbers, state} = :rand.uniform_s(100_000, state)
    normal(state, [@simpsons_character, @joiner, [numbers |> Integer.to_string()]])
  end

  @vape_flavor ~w{tobacco menthol mint fruit berry melon citrus lemon lime orange grape apple pear peach pineapple coconut banana mango watermelon strawberry blueberry raspberry blackberry kiwi cherry pomegranate dragonfruit guava lychee passionfruit papaya apricot plum nectarine}
  @vape_brand ~w{juul phix smok vuse blu njoy puffbar puffpl succ smoka choom chome bape vapestar smokemaster vapeman chouye sixltr}
  defp vape_guy(state) do
    normal(state, [@vape_brand, @joiner, @vape_flavor])
  end

  @e1_first ~w{walt gary weed reid curtis gilroy faze paper ricky king caden joseph fleezer bryden bradford dunstin yinz jurgen barney kirby aimee french regis darth dape tannin terrance bugs charlie marquife savannah brewer harley rando nate brody carl walton filbert bran cloak randy}
  @e1_last ~w{tremblay tasteman hashman gimball hong polanski chaser drama 2milli tang vahgo monsanto rogan sandy biden brantley hockendock checksin llubjana durepois knaselsen dinosaur shorty mann fry philbin hundo dode sperm fingerling lombardi tropicana o'beef fandango grouse knewer slice tussle bliscoe yummy sears fletcher 5000 barrows momo}
  defp e1(state) do
    normal(state, [@e1_first, @joiner, @e1_last])
  end

  @juggalo_adjective ~w{shaggy shaggar violent ill sick busted broken bad}
  @juggalo_name ~w{dope smoke a b c d e f g h i j k l m n o p q r s t u v w x y z beef turd}
  defp juggalo(state) do
    {numbers, state} = :rand.uniform_s(100_000, state)

    normal(state, [
      @juggalo_adjective,
      @joiner,
      @juggalo_name,
      @joiner,
      [numbers |> Integer.to_string()]
    ])
  end

  @cat_adjective ~w{big little cute funny smol small chungus beefy stinky evil devilish}
  @cat_name ~w{zedo piper littleone fatty lucky kirsten napoleon spruce june penny dandy blue bug ladybug moopsy molly ham }
  defp cat(state) do
    {numbers, state} = :rand.uniform_s(100_000, state)

    normal(state, [@cat_adjective, @joiner, @cat_name, @joiner, [numbers |> Integer.to_string()]])
  end

  @brand_adjective ~w{lover liker hater fan}

  defp brand(state) do
    normal(state, [@vowel, @open_phoneme, @close_phoneme, @vowel, @joiner, @brand_adjective])
  end
end
