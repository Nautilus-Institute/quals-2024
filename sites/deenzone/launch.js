window.async_sleep = function(ms) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, ms);
  });
};

let ticket = document.getElementById("ticket");
let launch = document.getElementById("launch");
let timer = document.getElementById("timer");
let error = document.getElementById("error");
let frame_wrapper = document.getElementById("framewrap");

let current_info = null;

let timeout = 120;
let max_time = 240;

let timer_iv = null;
let time_left = 0;
async function start_timer(left) {
  time_left = left;
  if (time_left > max_time)
    max_time = time_left;

  clearInterval(timer_iv);
  timer_iv = setInterval(() => {
    time_left -= 1;
    if (max_time - time_left > timeout) {
      enable_button();
    }
    if (time_left < 0) {
      clearInterval(timer_iv);
      timer.innerHTML = "No 🐟 Found";
      return;
    }
    timer.innerHTML = `Time left: ${time_left}`;
  }, 1000);
}


let launch_disabled = false;
function disable_button() {
  launch.classList.add("disabled");
  launch_disabled = true;
}
function enable_button() {
  launch.classList.remove("disabled");
  launch_disabled = false;
}

async function get_info() {
  let t = get_valid_ticket();
  if (!t) return null;
  let res = await fetch("/api/info", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ ticket: t })
  });
  res = await res.json();
  console.log(res);
  let err = res.error;
  if (err) {
    console.error(err);
    error.innerText = err;
    setTimeout(enable_button, 2000);
    return null;
  } else {
    error.innerText = '';
  }
  if (!res.token || res.left == 0) return null;
  return res;
}

function display_code_page(cmd, token) {
  frame_wrapper.style.display = "block";
  frame_wrapper.innerHTML = `<h3>We look forward to your arrival</h3> Please use early access code: ${token}`;
  document.querySelector(".deen-can").src = '/deen-go.png';
  document.getElementById("command").innerText = cmd;
}

function display_empty_page() {
  document.querySelector(".deen-can").src = '/deen-wait.png';
  frame_wrapper.style.display = "block";
  frame_wrapper.innerHTML = ``;
}

async function update_current_instance(info) {
  if (info) {
    current_info = info;
  } else {
    current_info = await get_info();
  }

  if (current_info == null || !current_info.token) {
    frame_wrapper.innerHTML = "";
    timer.innerText = "No running instance";
    display_empty_page();
    time_left = 0;
    return;
  }
  error.innerText = '';

  let host = current_info.host;
  let cmd = `nc ${host} ${current_info.port}`;

  display_code_page(cmd, current_info.token);

  start_timer(current_info.left);
}

launch.addEventListener("click", async function() {
  if (launch_disabled) return;


  let t = get_valid_ticket();
  if (!t) return;

  disable_button();
  clearTimeout(update_to);

  let res = await fetch("/api/launch", {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ ticket: t })
  });
  res = await res.json();
  console.log(res);
  let err = res.error;
  if (err) {
    console.error(err);
    error.innerText = err;
    setTimeout(enable_button, 2000);
    return;
  } else {
    error.innerText = '';
  }
  update_current_instance(res);

  timer.innerHTML = "Launching instance...";
  await async_sleep(2000);
});

function get_valid_ticket() {
  let t = ticket.value;
  if (t.length < 10)
    return null;
  if (t.indexOf('{') == -1)
    return null;
  if (t.indexOf('}') == -1)
    return null;
  return t;
}

let update_to = null;
{
  let t = localStorage.getItem("ticket");
  if (t) {
    ticket.value = t;
    clearTimeout(update_to);
    update_to = setTimeout(async function(){
      update_current_instance();
    }, 1000);
  } else {
    display_empty_page();
    timer.innerHTML = "No instance";
  }
}

ticket.addEventListener("change", async function() {
  let t = get_valid_ticket();
  if (!t) return;
  localStorage.setItem("ticket", t);
  clearTimeout(update_to);
  update_to = setTimeout(async function(){
    update_current_instance();
  }, 2000);
});
