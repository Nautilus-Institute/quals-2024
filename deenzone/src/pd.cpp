#include <ctime>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <chrono>
#include <streambuf>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <functional>
#include <netinet/tcp.h>
#include <random>

#include <sys/types.h>
#include <unistd.h>

#include <urcu/urcu-memb.h>	/* Userspace RCU flavor */
#include <urcu/rculist.h>	/* RCU list */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */
#include <urcu/rculfqueue.h>  /* RCU Lock-free queue */
#include <urcu/urcu.h>
#include <urcu/rculfhash.h>
#include <urcu/wfcqueue.h>

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <vector>

#include "pd.hpp"
int gConnectionCount = 0;
int gPasswordAttemptCount = 0;

static
void free_order_rcu(struct rcu_head *head) {
  Order *order = caa_container_of(head, struct Order, m_rcu_head);
  delete(order);
}

static
void free_trade_rcu(struct rcu_head *head) {
  Trade *trade = caa_container_of(head, struct Trade, m_rcu_head);
  //printf("[TID: %lu] Deleting trade %p\n", syscall(__NR_gettid), trade);
  delete(trade);
}

static
void free_client_list_entry_rcu(struct rcu_head *head) {
  // okay so we want to:
  //  alloc a new VipClientEntry using the current Entry
  //  delete the previous entry
  //  add the VipClientEntry to the vip_traders list.... how are we gonna get a reference to that man...fuck
  class ClientEntry *entry = caa_container_of(head, ClientEntry, m_rcu_head);
  class VipClientEntry *vip_entry = new VipClientEntry(*entry);
  //printf("[TID: %lu] Allocating vip_entry %p\n", syscall(__NR_gettid), vip_entry);
  struct cds_hlist_head *vip_head = (struct cds_hlist_head *)entry->fuck;
  delete(entry);
  cds_hlist_add_head_rcu(&vip_entry->m_hlist_node, vip_head);
}

// some sort mofos
template <class T>
bool sortTickerDescending(const T *lhs, const T *rhs) {
  return lhs->m_ticker < rhs->m_ticker;
}

template <class T>
bool sortTickerAscending(const T *lhs, const T *rhs) {
  return lhs->m_ticker > rhs->m_ticker;
}

template <class T>
bool sortTimeDescending(const T *lhs, const T *rhs) {
  if (lhs->m_timestamp.tv_sec != rhs->m_timestamp.tv_sec) {
    return lhs->m_timestamp.tv_sec < rhs->m_timestamp.tv_sec;
  }
  else {
    return lhs->m_timestamp.tv_nsec < rhs->m_timestamp.tv_nsec;
  }
}

template <class T>
bool sortTimeAscending(const T *lhs, const T *rhs) {
  if (lhs->m_timestamp.tv_sec != rhs->m_timestamp.tv_sec) {
    return lhs->m_timestamp.tv_sec > rhs->m_timestamp.tv_sec;
  }
  else {
    return lhs->m_timestamp.tv_nsec > rhs->m_timestamp.tv_nsec;
  }
}

template <typename T>
using CompareFunction = std::function<bool(const T*, const T*)>;

template <typename T>
std::array<CompareFunction<T>, 4> comparisonFunctions = {
    &sortTimeDescending<T>,
    &sortTimeAscending<T>,
    &sortTickerDescending<T>,
    &sortTickerAscending<T>
};

bool leftOrderOlder(Order *lhs, Order *rhs) {
  if (lhs->m_timestamp.tv_sec != rhs->m_timestamp.tv_sec) {
    return (lhs->m_timestamp.tv_sec > rhs->m_timestamp.tv_sec);
  }
  else {
    return (lhs->m_timestamp.tv_sec >= rhs->m_timestamp.tv_sec);
  }
}

// ############
// ## Client ##
// ############
Client::Client(std::string username, std::string password, float balance, uint64_t num_trades) {
  m_username = username;
  m_password = password;
  m_balance = balance;
  m_num_trades = num_trades;
  m_hash = std::hash<std::string>{}(m_username);
  m_is_authd = false;
  m_is_vip = num_trades >= VIP_THRESHOLD_SILVER ? true : false;
  m_sort_pref = kTimeDec;
}

Client::Client() {
};

std::string Client::asString(char *indent) {
  std::stringstream ss;
  ss << "[ " << m_username << " ]\n";
  ss << indent << "password: " << m_password << "\n";
  ss << indent << "balance: " << m_balance << "\n";
  ss << indent << "num trades: " << m_num_trades << "\n";
  ss << indent << "user_id: " << m_hash << "\n";
  return ss.str();
}

// #################
// ## ClientEntry ##
// #################

ClientEntry::ClientEntry(Client *client) {
    m_balance = client->m_balance;
    m_username = client->m_username;
    m_password = client->m_password;
    m_hash = client->m_hash;
    m_is_authd = client->m_is_authd;
    m_num_trades = client->m_num_trades;
}

std::string ClientEntry::asString(char *indent) {
  std::stringstream ss;
  ss << indent << "username: " << m_username << "\n";
  return ss.str();
}

// ####################
// ## VipClientEntry ##
// ####################
VipClientEntry::VipClientEntry(ClientEntry &entry) {
    m_balance = entry.m_balance;
    m_username = entry.m_username;
    m_password = entry.m_password;
    m_hash = entry.m_hash;
    m_is_authd = entry.m_is_authd;
    m_num_trades = entry.m_num_trades;
    m_vip_level = VipClientEntry::GetVipLevel(m_num_trades);
}

VipClientEntry::VipClientEntry(Client *client) {
    m_balance = client->m_balance;
    m_username = client->m_username;
    m_password = client->m_password;
    m_hash = client->m_hash;
    m_is_authd = client->m_is_authd;
    m_num_trades = client->m_num_trades;
    m_vip_level = VipClientEntry::GetVipLevel(m_num_trades);
}

std::string VipClientEntry::asString(char *indent) {
  std::stringstream ss;
  ss << indent << "username: " << m_username << "\n";
  ss << indent << "vip level: " << m_vip_level << "\n";
  return ss.str();
}

// ################
// ## Order Book ##
// ################
OrderBook::OrderBook(void) {
  pthread_mutex_init(&m_orderq_lock, NULL);
  pthread_cond_init(&m_orderq_cond, NULL);

  pthread_mutex_init(&m_matchq_lock, NULL);
  pthread_cond_init(&m_matchq_cond, NULL);
  m_trade_history = new TradeHistory();
}

// ##############
// ## Position ##
// ##############
Position::Position(std::string ticker, int64_t quantity) {
  m_ticker = ticker;
  m_quantity = quantity;
}

std::string Position::asString(char *indent) {
  std::stringstream ss;
  ss << indent << "ticker: " << m_ticker << "\n";
  ss << indent << "quantity: " << m_quantity << "\n";
  return ss.str();
};

// ###################
// ## Position List ##
// ###################
PositionList::PositionList(void) {
  pthread_mutex_init(&m_list_lock, NULL);
}

Position *PositionList::getPosition(std::string ticker) {
  return m_list.count(ticker) == 0 ? nullptr : m_list[ticker];
}

int PositionList::updatePosition(std::string ticker, int64_t delta) {
  Position *pos = getPosition(ticker);
  // if there's no position for this ticker, but the delta is positive
  // then create a new position
  if (!pos && (delta > 0)) {
    Position *pos = new Position(ticker, delta);
    m_list[ticker] = pos;
    return 0;
  }

  else if (pos) {
    // if we already have a pos and the delta is pos
    // then just add the new deens
    if (delta > 0) {
      pos->m_quantity += delta;
      return 0;
    }
    // if we already have a position for this ticker and the delta is negative
    // make sure we have enough
    else {
      if (pos->m_quantity >= (-1*delta)) {
        pos->m_quantity += delta;
        if (pos->m_quantity == 0) {
          m_list.erase(ticker);
        }
        return 0;
      }
      else {
        return -1;
      }
    }
  }
  return -1;
}

// ###################
// ## Position Book ##
// ###################
PositionBook::PositionBook(void) {
  pthread_mutex_init(&m_book_lock, NULL);
}

void PositionBook::createNewPositionList(Client *c) {
  PositionList *pl = new PositionList();
  pthread_mutex_lock(&m_book_lock);
  m_book[c->m_hash] = pl;
  pthread_mutex_unlock(&m_book_lock);
  return;
}

PositionList *PositionBook::getPositionListForClient(std::size_t client_hash) {
  return m_book.count(client_hash) == 0 ? nullptr : m_book[client_hash];
}

int PositionBook::createOrUpdatePosition(std::size_t client_hash, std::string ticker, int64_t delta) {
  int ret = -1;
  PositionList *pl = getPositionListForClient(client_hash);
  if (!pl) {
    // we should never hit this..
    return -1;
  }
  pthread_mutex_lock(&pl->m_list_lock);
  ret = pl->updatePosition(ticker, delta);
  pthread_mutex_unlock(&pl->m_list_lock);
  return ret;
}

// ####################
// ## Trader History ##
// ####################
TradeHistory::TradeHistory(void) {
  m_hist_size = 0;
  m_first = nullptr;
};

void TradeHistory::addTrade(Trade *t) {
  urcu_memb_read_lock();
  struct cds_list_head *temp = nullptr;
  // first entry. Set our last ptr to this mofo
  if (!m_first) {
    //printf("Setting a last ptr\n");
    m_first = &t->m_list_node;
  }
  if (m_hist_size < MAX_TRADE_HIST) {
    //printf("Normal trade add)\n");
    cds_list_add_tail_rcu(&t->m_list_node, &m_list_trades);
    m_hist_size++;
  }
  // remove the first guy
  else {
    //printf("going to remove a man\n");
    temp = m_first;
    // so we need to acquire the trade before this call, and hold it past the free_trade_rcu call
    cds_list_del_rcu(m_first);
    if (temp->next == (struct cds_list_head *)&m_list_trades) {
      m_first = nullptr;
    }
    else {
      m_first = temp->next;
    }
    cds_list_add_tail_rcu(&t->m_list_node, &m_list_trades);
    Trade *trade_to_delete = caa_container_of(temp, struct Trade, m_list_node);
    urcu_memb_call_rcu(&trade_to_delete->m_rcu_head, free_trade_rcu);
  }
  urcu_memb_read_unlock();
}

// ####################
// ## Trader Endinge ##
// ####################
TradingEngine::TradingEngine(TradingPlatform *platform) {
  m_platform = platform;
}

void TradingEngine::run(void) {
  while (1) {
    pthread_mutex_lock(&m_platform->m_orderbook->m_matchq_lock);
    while(m_platform->m_orderbook->m_matchq.empty()) {
      pthread_cond_wait(&m_platform->m_orderbook->m_matchq_cond, &m_platform->m_orderbook->m_matchq_lock);
    }
    Trade *trade = m_platform->m_orderbook->m_matchq.front();
    m_platform->m_orderbook->m_matchq.pop();
    pthread_mutex_unlock(&m_platform->m_orderbook->m_matchq_lock);
    //printf("Got a trade to execute!\n");
    //printf("%s\n", trade->asString().c_str());
    execute(trade);
  }
}

void TradingEngine::execute(Trade *trade) {
  // give the seller money
  float seller_earned = trade->m_price_per * trade->m_quantity;
  pthread_mutex_lock(&m_platform->m_client_map_lock);
  Client *seller = m_platform->getClient(trade->m_seller_id);
  seller->m_balance += seller_earned;

  // update the buyers position (and potentially money if we credit them back any)
  Client *buyer = m_platform->getClient(trade->m_buyer_id);
  if (trade->m_price_per < trade->m_buyer_ask) {
    float buyer_refund = (trade->m_buyer_ask - trade->m_price_per) * trade->m_quantity;
    buyer->m_balance += buyer_refund;
  }
  assert(trade->m_quantity > 0);
  m_platform->m_posbook->createOrUpdatePosition(trade->m_buyer_id, trade->m_ticker, trade->m_quantity);
  // now add this to trade history
  m_platform->m_orderbook->m_trade_history->addTrade(trade);
  m_platform->maybePromoteTrader(buyer);
  m_platform->maybePromoteTrader(seller);
  pthread_mutex_unlock(&m_platform->m_client_map_lock);
  return;
}

// #####################
// ## Matching Engine ##
// #####################
MatchingEngine::MatchingEngine(TradingPlatform *platform) {
  m_platform = platform;
}

void MatchingEngine::match() {
  bool got_match = true;
  while (got_match) {
    got_match = false;
    auto buy_it = m_platform->m_orderbook->m_buys.begin();
    auto sell_it = m_platform->m_orderbook->m_sells.begin();
    while (buy_it != m_platform->m_orderbook->m_buys.end() && sell_it != m_platform->m_orderbook->m_sells.end()) {
      Order* buy_order = *buy_it;
      Order* sell_order = *sell_it;
      // ticker match and prices are good
      if (buy_order->m_price >= sell_order->m_price && buy_order->m_ticker == sell_order->m_ticker) {
        //printf("OH HELL YEAH, WE GOT A MATCH BRO\n");
        int64_t quantity = std::min(buy_order->m_quantity, sell_order->m_quantity);
        //printf("buy_order->m_quantity: %lu\nsell_order->m_quantity: %lu\n", buy_order->m_quantity, sell_order->m_quantity);

        buy_order->m_quantity -= quantity;
        sell_order->m_quantity -= quantity;

        // oldest order wins the price.
        // so if the buy order is older, defer to the buyer price which is greater than or equal to what the seller was asking
        float price = leftOrderOlder(buy_order, sell_order) ? buy_order->m_price : sell_order->m_price;
        
        Trade *trade = new Trade(buy_order->m_client_hash, sell_order->m_client_hash, buy_order->m_ticker, quantity, price, buy_order->m_price, sell_order->m_price);
        got_match = true;

        if (buy_order->m_quantity == 0) {
          //printf("The buy mofo should be donezo\n");
          buy_it = m_platform->m_orderbook->m_buys.erase(buy_it);
          cds_hlist_del_rcu(&buy_order->m_hlist_node);
          /*
           * We can only reclaim memory after a grace
           * period has passed after cds_hlist_del_rcu().
           */
          urcu_memb_call_rcu(&buy_order->m_rcu_head, free_order_rcu);
        } else {
          //printf("Moving to the next buy order\n");
          ++buy_it;
        }

        if (sell_order->m_quantity == 0) {
          //printf("The sell mofo should be donezo\n");
          sell_it = m_platform->m_orderbook->m_sells.erase(sell_it);
          cds_hlist_del_rcu(&sell_order->m_hlist_node);
          /*
           * We can only reclaim memory after a grace
           * period has passed after cds_hlist_del_rcu().
           */
          urcu_memb_call_rcu(&sell_order->m_rcu_head, free_order_rcu);
        } else {
          ++sell_it;
        }

        m_platform->submitTrade(trade);
      }

      else if (buy_order->m_ticker < sell_order->m_ticker) {
        buy_it++;
      }
      // ticker match buy price mismatch
      else {
        sell_it++;
      }
    }
  }
}


void MatchingEngine::run(void) {
  uint64_t sell_orders = 0;
  uint64_t buy_orders = 0;
  while (1) {
    pthread_mutex_lock(&m_platform->m_orderbook->m_orderq_lock);
    while(m_platform->m_orderbook->m_orderq.empty()) {
      pthread_cond_wait(&m_platform->m_orderbook->m_orderq_cond, &m_platform->m_orderbook->m_orderq_lock);
    }
    Order *order = m_platform->m_orderbook->m_orderq.front();
    m_platform->m_orderbook->m_orderq.pop();
    pthread_mutex_unlock(&m_platform->m_orderbook->m_orderq_lock);
    if (order->m_type == BUY) {
      //printf("Got a buy order! %lu\n", buy_orders);
      buy_orders++;
      m_platform->m_orderbook->m_buys.insert(order);
      cds_hlist_add_head_rcu(&order->m_hlist_node, &m_platform->m_orderbook->m_hlist_buys);
    }
    else {
      //printf("Got a sell order! %lu\n", sell_orders);
      sell_orders++;
      m_platform->m_orderbook->m_sells.insert(order);
      cds_hlist_add_head_rcu(&order->m_hlist_node, &m_platform->m_orderbook->m_hlist_sells);
    }
    match();
  }
}

// ###########
// ## Trade ##
// ###########
Trade::Trade(std::size_t buyer, std::size_t seller, std::string ticker, int64_t quantity, float price_per, float buyer_ask, float seller_ask) {
  m_buyer_id = buyer;
  m_seller_id = seller;
  m_ticker = ticker;
  m_quantity = quantity;
  m_price_per = price_per;
  m_buyer_ask = buyer_ask;
  m_seller_ask = seller_ask;
  timespec_get(&m_timestamp, TIME_UTC);
}

std::string Trade::asString(char *indent) {
      std::stringstream ss;
      //printf("%p\n", this);
      ss << indent << "buyer_id: " << m_buyer_id<< "\n";
      ss << indent << "seller_id: " << m_seller_id<< "\n";
      ss << indent << "ticker: " << m_ticker << "\n";
      ss << indent << "price: " << m_price_per << "\n";
      ss << indent << "quantity: " << m_quantity << "\n";
      ss << indent << "executed at: " << m_timestamp.tv_sec << "." << m_timestamp.tv_nsec << "\n";
      return ss.str();
}

// ###########
// ## Order ##
// ###########
Order::Order(ORDER_TYPE type, std::size_t hash) {
  m_type = type;
  m_client_hash = hash;
  timespec_get(&m_timestamp, TIME_UTC);
}

Order::Order(ORDER_TYPE type, std::size_t hash, std::string ticker, int64_t quantity, float price) {
  m_type = type;
  m_client_hash = hash;
  m_ticker = ticker;
  m_quantity = quantity;
  m_price = price;
  timespec_get(&m_timestamp, TIME_UTC);
}

std::string Order::asString(char *indent) {
      std::stringstream ss;
      ss << indent << "client_id: " << m_client_hash << "\n";
      ss << indent << "ticker: " << m_ticker << "\n";
      ss << indent << "price: " << m_price << "\n";
      ss << indent << "quantity: " << m_quantity << "\n";
      ss << indent << "submission time: " << m_timestamp.tv_sec << "." << m_timestamp.tv_nsec << "\n";
      return ss.str();
}

int Order::getInfo(Session *s) {
  s->sendMsg("[?] Ticker\n> ");
  char temp[256] = {0};
  int n = 0;
  if (s->recvUntil(temp, sizeof(temp)) < 0 ) {
    return -1;
  }
  m_ticker = temp;

  s->sendMsg("[?] Quantity\n> ");
  m_quantity = s->readUint64();

  s->sendMsg("[?] Price\n> ");
  m_price = s->readFloat();
  if (m_price < 0) {
    return -1;
  }
  return 0;
}

// #############
// ## Session ##
// #############
Session::Session(TradingPlatform *platform, int fd) {
  m_active_client = nullptr;
  m_platform = platform;
  m_fd = fd;
}

static
void interact_thread_cleanup(void *arg) {
  //printf("Cleanup handler here\n");
  Session *session = (Session *)arg;
  if (session->m_active_client) {
    session->m_active_client->m_is_authd = false;
    session->m_active_client = nullptr;
  }
  close(session->m_fd);
  delete(session);
}

void *interact_thread_fn(void *arg) {
  Session *session = (Session *)arg;
  pthread_cleanup_push(interact_thread_cleanup, (void *)session);
  session->interact();
  //printf("[!] Session ending\n");
  close(session->m_fd);
  free(session);
  pthread_cleanup_pop(0);
  return nullptr;
}

Order *Session::createOrder(ORDER_TYPE type) {
  struct Order *order = new Order(type, m_active_client->m_hash);
  if (order->getInfo(this) < 0) {
    sendMsg("[!] Invalid order\n");
    delete order;
    order = nullptr;
  }
  return order;
}

void Session::viewActiveAccount(void) {
  sendMsg(m_active_client->asString("\t").c_str());
  sendMsg("\tPositions:\n");
  PositionList *pl = m_platform->m_posbook->getPositionListForClient(m_active_client->m_hash);
  pthread_mutex_lock(&pl->m_list_lock);
  for (auto it = pl->m_list.begin(); it != pl->m_list.end(); it++) {
    Position *pos = it->second;
    sendMsg(pos->asString("\t\t").c_str());
    sendMsg("\n---\n");
  }
  pthread_mutex_unlock(&pl->m_list_lock);
}

int Session::loggedIn() {
  while (1) {
    char buf[32];
    int sort_pref = 0;
    memset(buf, 0, 32);
    sendMsg("1) Buy\n");
    sendMsg("2) Sell\n");
    sendMsg("3) View account info\n");
    sendMsg("4) View current orders\n");
    sendMsg("5) View recent trades\n");
    sendMsg("6) View list of clients\n");
    sendMsg("7) Display preference\n");
    sendMsg("8) Logout\n");
    sendMsg("> ");
    int choice = readInt();
    Order *order = nullptr;
    switch(choice) {
      case 1:
      case 2:
        order = createOrder((ORDER_TYPE)(choice-1));
        if (order && m_platform->isValidOrder(order)) {
          m_platform->submitOrder(order);
        }
        else {
          sendMsg("[!] Invalid order\n");
          delete order;
          order = nullptr;
        }
        break;
      case 3:
        viewActiveAccount();
        break;
      case 4:
        m_platform->listOrders(this);
        break;
      case 5:
        m_platform->listTrades(this);
        break;
      case 6:
        if (m_active_client->m_is_vip == false) {
          sendMsg("[!] This functionality is for VIP members only\n");
        } else {
          m_platform->ListClients(this);
        }
        break;
      case 7: // settings
        sendMsg("1) Timestamp Descending\n");
        sendMsg("2) Timestamp Ascending\n");
        sendMsg("3) Ticker Descending\n");
        sendMsg("4) Ticker Ascending\n");
        sendMsg("> ");
        sort_pref = readInt();
        if (sort_pref > 0 && sort_pref <= kSortMax) {
          m_active_client->m_sort_pref = (enum SortFunc)(sort_pref-1);
        }
        else {
          sendMsg("[!] Invalid Choice\n");
        }
        break;
      case 8:
        return 0;
      default:
        sendMsg("[!] Invalid choice\n");
        break;
    }
  }
  return 0;
}

void Session::interact() {
  while (1) {
    sendMsg("\n1) Create an account\n");
    sendMsg("2) Login\n");
    sendMsg("3) Exit\n");
    sendMsg("> ");
    int choice = readInt();
    int err = -1;
    Client *client = nullptr;
    switch (choice) {
      case 1:
        client = m_platform->newAccount(this);
        break;
      case 2:
        err = m_platform->login(this);
        if (err == 0) {
          sendMsg("[+] Welcome ");
          sendMsg(m_active_client->m_username.c_str());
          sendMsg("\n");
          err = loggedIn();
          m_active_client->m_is_authd = false;
          m_active_client = nullptr;
        }
        break;
      case 3:
        // TODO: clean up active client here maybe?
        return;
      default:
        sendMsg("[!] Invalid choice\n");
    }
  }
  return;
}

int Session::sendMsg(const char* msg) {
  int err = send(m_fd, msg, strlen(msg), MSG_NOSIGNAL);
  if (err < 0) {
    exit(-1);
  }
  return err;
}

int Session::recvUntil(void *buf, size_t n) {
  for (int i = 0; i < n; i++) {
    char c;
    if (read(m_fd, &c, 1) != 1) {
      // no short reads plz
      exit(-1);
    }
    ((char *)buf)[i] = c;
    if (c == '\n') {
      ((char *)buf)[i] = 0;
      return i;
    }
  }
  ((uint8_t *)buf)[n-1] = 0;
  return n;
}

int Session::readInt() {
  char buf[0x10] = {0};
  recvUntil(&buf, sizeof(buf));
  return atoi(buf);
}

int64_t Session::readInt64() {
  char buf[0x10] = {0};
  recvUntil(&buf, sizeof(buf));
  return(std::strtoll(buf, nullptr, 10));
}

uint64_t Session::readUint64() {
  char buf[0x10] = {0};
  recvUntil(&buf, sizeof(buf));
  return(std::strtoull(buf, nullptr, 10));
}

float Session::readFloat() {
  char buf[0x10] = {0};
  recvUntil(&buf, sizeof(buf));
  return(std::strtof(buf, nullptr));
}

// ######################
// ## Trading Platform ##
// ######################
TradingPlatform::TradingPlatform(std::string config_file, int port, char *token) {
  m_port = port;
  m_token = token;
  std::ifstream file(config_file);
  std::string str((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
  rapidjson::Document d;
  d.Parse(str.c_str());

  const rapidjson::Value& arr = d["tickers"];
  for (rapidjson::SizeType i = 0; i < arr.Size(); i++) {
    m_tickers.push_back(arr[i].GetString());
  }
  m_dist.param(param_t(0, m_tickers.size()-1));

  m_orderbook = new OrderBook();
  m_posbook = new PositionBook();
  pthread_mutex_init(&m_client_map_lock, NULL);

  const rapidjson::Value& acc_arr = d["accounts"];
  for (rapidjson::SizeType i = 0; i < acc_arr.Size(); i++) {
    const rapidjson::Value& acc = acc_arr[i];
    Client *new_client = newAccount(acc["username"].GetString(), acc["password"].GetString(), acc["balance"].GetFloat(), acc["num_trades"].GetInt64());
    const rapidjson::Value& pos_arr = acc["positions"];
    rapidjson::SizeType j = 0;
    for (j = 0; j < pos_arr.Size(); j++) {
      const rapidjson::Value& pos = pos_arr[j];
      m_posbook->createOrUpdatePosition(new_client->m_hash, pos["ticker"].GetString(), pos["quantity"].GetInt64());
    }
    const rapidjson::Value& order_arr = acc["orders"];
    for (j = 0; j < order_arr.Size(); j++) { // TODO: go through valid order here instead to remove funds...
      pthread_mutex_lock(&m_orderbook->m_orderq_lock);
      const rapidjson::Value& order = order_arr[j];
      Order *new_order = new Order((ORDER_TYPE)order["type"].GetInt(), new_client->m_hash, order["ticker"].GetString(), order["quantity"].GetInt64(), order["price"].GetFloat());
      m_orderbook->m_orderq.push(new_order);
      pthread_mutex_unlock(&m_orderbook->m_orderq_lock);
    }
    if (j > 0) {
      pthread_mutex_lock(&m_orderbook->m_orderq_lock);
      pthread_cond_signal(&m_orderbook->m_orderq_cond);
      pthread_mutex_unlock(&m_orderbook->m_orderq_lock);
    }
  }
};

void TradingPlatform::createEntryForClient(Client *client) {
  if (client->m_is_vip == false) {
    class ClientEntry *entry = new ClientEntry(client);
    cds_hlist_add_head_rcu(&entry->m_hlist_node, &m_hlist_clients);
  }
  else {
    class VipClientEntry *vip_entry = new VipClientEntry(client);
    cds_hlist_add_head_rcu(&vip_entry->m_hlist_node, &m_hlist_vip_clients);
  }
}

void TradingPlatform::ListClients(Session *s) {
  s->sendMsg("[+] Vip Clients:\n");
  VipClientEntry *vip_entry = nullptr;
  ClientEntry *entry = nullptr;
  urcu_memb_read_lock();
  cds_hlist_for_each_entry_rcu_2(vip_entry, &m_hlist_vip_clients, m_hlist_node) {
    s->sendMsg(vip_entry->asString("\t").c_str());
    s->sendMsg("\n");
  }

  s->sendMsg("----\n[+] Clients:\n");
  cds_hlist_for_each_entry_rcu_2(entry, &m_hlist_clients, m_hlist_node) {
    s->sendMsg(entry->asString("\t").c_str());
    s->sendMsg("\n");
  }
  urcu_memb_read_unlock();
}

ClientEntry *TradingPlatform::getClientEntryFromList(std::size_t hash) {
  ClientEntry *entry = nullptr;
  cds_hlist_for_each_entry_rcu_2(entry, &m_hlist_clients, m_hlist_node) {
    if (entry->m_hash == hash)
      return entry;
  }
  return nullptr;
}

void TradingPlatform::maybePromoteTrader(Client *client) {
  client->m_num_trades++;
  uint64_t num_trades = client->m_num_trades;
  if (client->m_is_vip)
    return;
  if (client->m_num_trades == VIP_THRESHOLD_SILVER) {
    client->m_is_vip = true;
    urcu_memb_read_lock();
    ClientEntry *entry = getClientEntryFromList(client->m_hash);
    entry->fuck = (void *)&m_hlist_vip_clients;
    entry->m_num_trades = num_trades;
    cds_hlist_del_rcu(&entry->m_hlist_node);
    urcu_memb_call_rcu(&entry->m_rcu_head, free_client_list_entry_rcu);
    urcu_memb_read_unlock();
  }
}

void TradingPlatform::listTrades(Session *s) {
  Trade *trade = nullptr;
  std::vector<Trade *> vec;
  urcu_memb_read_lock();
  cds_list_for_each_entry_rcu(trade, &m_orderbook->m_trade_history->m_list_trades, m_list_node) {
    //printf("pushing back trade %p\n", trade);
    vec.push_back(trade);
  }
  
  auto compare = comparisonFunctions<Trade>[s->m_active_client->m_sort_pref];
  std::sort(vec.begin(), vec.end(), compare);

  for (int i = 0; i < vec.size(); i++) {
    trade = vec[i];
    //printf("Trade: %p\n", trade);
    std::string trade_str = trade->asString("\t");
    s->sendMsg(trade_str.c_str());
    s->sendMsg("------------------------------\n");
  }
  urcu_memb_read_unlock();
};

void TradingPlatform::listOrders(Session *s) {
  //printf("Listing orders!\n");
  s->sendMsg("[+] Current Sell Orders:\n");
  Order *order = nullptr;
  std::vector<Order *> sells;
  std::vector<Order *> buys;

  auto compare = comparisonFunctions<Order>[s->m_active_client->m_sort_pref];
  urcu_memb_read_lock();
  cds_hlist_for_each_entry_rcu_2(order, &m_orderbook->m_hlist_sells, m_hlist_node) {
    sells.push_back(order);
  }

  std::sort(sells.begin(), sells.end(), compare);

  for (int i = 0; i < sells.size(); i++) {
    order = sells[i];
    std::string order_str = order->asString("\t");
    s->sendMsg(order_str.c_str());
    s->sendMsg("------------------------------\n");
  }
  urcu_memb_read_unlock();
  s->sendMsg("\n==============================\n[+] Current Buy Orders:\n");
  order = nullptr;

  urcu_memb_read_lock();
  cds_hlist_for_each_entry_rcu_2(order, &m_orderbook->m_hlist_buys, m_hlist_node) {
    buys.push_back(order);
  }

  std::sort(buys.begin(), buys.end(), compare);

  for (int i = 0; i < buys.size(); i++) {
    order = buys[i];
    std::string order_str = order->asString("\t");
    s->sendMsg(order_str.c_str());
    s->sendMsg("------------------------------\n");
  }
  s->sendMsg("\n\n");
  urcu_memb_read_unlock();
  //printf("DONE SENDING ORDERS\n\n");
}

Client *TradingPlatform::newAccount(Session *s) {
  Client *new_client = NULL;
  char username[64] = {0};
  char password[64] = {0};
  int n = 0;
  s->sendMsg("username> ");
  n = s->recvUntil(username, sizeof(username));
  if (n <= 0) {
    s->sendMsg("\n[!] Bad username\n");
    return nullptr;
  }

  pthread_mutex_lock(&m_client_map_lock);
  std::size_t hash = std::hash<std::string>{}(username);
  if (m_client_map.count(hash)) {
    s->sendMsg("[!] User already exists!\n");
    pthread_mutex_unlock(&m_client_map_lock);
    return nullptr;
  }

  s->sendMsg("\npassword> ");
  n = s->recvUntil(password, sizeof(password));
  if (n <= 0) {
    s->sendMsg("\n[!] Bad password\n");
    pthread_mutex_unlock(&m_client_map_lock);
    return nullptr;
  }

  new_client = new Client(username, password, 25.0, 0);
  m_client_map[hash] = new_client;
  createEntryForClient(new_client);
  // create a position list for the new client
  m_posbook->createNewPositionList(new_client);
  // grant the user a complimentary deen
  std::string random_deen = m_tickers[m_dist(m_rd)];
  m_posbook->createOrUpdatePosition(new_client->m_hash, random_deen, 1);
  pthread_mutex_unlock(&m_client_map_lock);
  return new_client;
}

Client *TradingPlatform::newAccount(std::string username, std::string password, float balance, uint64_t num_trades) {
  //printf("newAccount being created for %s which has num_trades of: %lu\n", username.c_str(), num_trades);
  Client *new_client = NULL;

  pthread_mutex_lock(&m_client_map_lock);
  std::size_t hash = std::hash<std::string>{}(username);
  if (m_client_map.count(hash)) {
    pthread_mutex_unlock(&m_client_map_lock);
    return nullptr;
  }

  new_client = new Client(username, password, balance, num_trades);
  m_client_map[hash] = new_client;
  createEntryForClient(new_client);
  // create a position list for the new client
  m_posbook->createNewPositionList(new_client);
  pthread_mutex_unlock(&m_client_map_lock);
  return new_client;
}

// NOT RESPONSIBLE FOR LOCKING
Client *TradingPlatform::getClient(std::size_t hash) {
  if (m_client_map.count(hash) == 0) {
    return nullptr;
  }
  return m_client_map[hash];
}

void TradingPlatform::submitTrade(Trade *trade) {
  pthread_mutex_lock(&m_orderbook->m_matchq_lock);
  m_orderbook->m_matchq.push(trade);
  pthread_cond_signal(&m_orderbook->m_matchq_cond);
  pthread_mutex_unlock(&m_orderbook->m_matchq_lock);
  return;
}

void TradingPlatform::submitOrder(Order *order) {
  pthread_mutex_lock(&m_orderbook->m_orderq_lock);
  m_orderbook->m_orderq.push(order);
  pthread_cond_signal(&m_orderbook->m_orderq_cond);
  pthread_mutex_unlock(&m_orderbook->m_orderq_lock);
  return;
}

bool TradingPlatform::isValidOrder(struct Order *order) {
  Client *client = nullptr;

  // so for a buy order, we need to check the client has enough funds
  if (order->m_type == BUY) {
    pthread_mutex_lock(&m_client_map_lock);
    client = getClient(order->m_client_hash);
    float needed_amnt = order->m_price * order->m_quantity;
    if (!(client->m_balance >= needed_amnt)) {
      //printf("client: %s  balance: %f   needed: %f\n", client->m_username.c_str(), client->m_balance, needed_amnt);
      pthread_mutex_unlock(&m_client_map_lock);
      return false;
    }
    // yeah this is weird to do here but I don't want to deal with the possibility of them not having the necessary funds at the time of trade execution..
    client->m_balance -= needed_amnt;
    pthread_mutex_unlock(&m_client_map_lock);
    return true;
  }

  // for a sell order, we need to check the clients positions in the pos book
  else {
    int err = m_posbook->createOrUpdatePosition(order->m_client_hash, order->m_ticker, (-1*order->m_quantity));
    return err < 0 ? false : true;
  }
}

int TradingPlatform::login(Session *s) {
  Client *client = NULL;
  char username[64] = {0};
  char password[64] = {0};
  int n = 0;
  s->sendMsg("username> ");
  n = s->recvUntil(username, sizeof(username));
  if (n <= 0) {
    s->sendMsg("\n[!] Bad username\n");
    return -1;
  }
  // TODO: Fix up the logic around active_client vs client authd. There is redundancy here

  pthread_mutex_lock(&m_client_map_lock);
  std::size_t hash = std::hash<std::string>{}(username);
  if (m_client_map.count(hash) != 1) {
    s->sendMsg("[!] No such user\n");
    pthread_mutex_unlock(&m_client_map_lock);
    return -1;
  }
  client = m_client_map[hash];
  if (client->m_is_authd) {
    s->sendMsg("[!] Ongoing session exists");
    pthread_mutex_unlock(&m_client_map_lock);
    return -1;
  }

  s->sendMsg("\npassword> ");
  n = s->recvUntil(password, sizeof(password));
  if (n <= 0) {
    s->sendMsg("\n[!] Bad password\n");
    pthread_mutex_unlock(&m_client_map_lock);
    return -1;
  }

  if (std::string(password).compare(client->m_password)) {
    s->sendMsg("[!] Incorrect password\n");
    pthread_mutex_unlock(&m_client_map_lock);
    if (++gPasswordAttemptCount == MAX_PASSWORD_ATTEMPTS) {
      exit(-1);
    }
    return -1;
  }

  client->m_is_authd = true;
  s->setActiveClient(client);
  pthread_mutex_unlock(&m_client_map_lock);
  return 0;
}

void TradingPlatform::startListen(void) {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in address = {0};
  int opt = 1;
  uint8_t token_buf[64];
  if (server_fd < 0) {
    perror("socket");
    return;
  }

  if (setsockopt(server_fd, SOL_SOCKET,
                 SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt");
    return;
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(m_port);

  if (bind(server_fd, (struct sockaddr*)&address,sizeof(address)) < 0) {
    perror("bind");
    return;
  }
  
  if (listen(server_fd, 10) < 0) {
    perror("listen");
    return;
  }

  // accept connections
  while (1) {
    memset(token_buf, 0, sizeof(token_buf));
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
      perror("accept");
      return;
    }
    pthread_t session_thread;
    Session *session = new Session(this, client_fd);
    session->sendMsg("Welcome to the DeenZone!\n");
    // ask for the token first if we have one
    if (m_token != "") {
      session->sendMsg("Please enter your early access token to continue:\n");
      session->recvUntil(token_buf, sizeof(token_buf));
      if ((char *)token_buf != m_token) {
        session->sendMsg("Incorrect token\n");
        close(session->m_fd);
        delete(session);
        continue;
      }
    }
    if (++gConnectionCount == MAX_CONNECTIONS) {
      exit(-1);
    }
    pthread_create(&session_thread, NULL, interact_thread_fn, (void *)session);
  }

  return;
}


void *trading_thread_fn(void *arg) {
   TradingEngine *trading_engine = static_cast<TradingEngine*>(arg);
   trading_engine->run();
   return nullptr;
}

void *matching_thread_fn(void *arg) {
   MatchingEngine *matching_engine = static_cast<MatchingEngine*>(arg);
   matching_engine->run();
   return nullptr;
}

void *connection_thread_fn(void *arg) {
   TradingPlatform *platform = static_cast<TradingPlatform*>(arg);
   platform->startListen();
   return nullptr;
}

int main(int argc, char *argv[]) {
  int port = PORT;
  char *token = "";
  if (argc > 1) {
    port = atoi(argv[1]);
  }
  if (argc > 2) {
    token = argv[2];
  }
  pthread_t matching_thread;
  pthread_t trading_thread;
  pthread_t connection_thread;

  TradingPlatform *platform = new TradingPlatform("config.json", port, token);
  MatchingEngine *matching_engine = new MatchingEngine(platform);
  TradingEngine *trading_engine = new TradingEngine(platform);

  pthread_create(&matching_thread, NULL, matching_thread_fn, (void *)matching_engine);
  pthread_create(&trading_thread, NULL, trading_thread_fn, (void *)trading_engine);
  pthread_create(&connection_thread, NULL, connection_thread_fn, (void *)platform);

  pthread_join(connection_thread, NULL);
  pthread_join(matching_thread, NULL);
  pthread_join(trading_thread, NULL);
  return 0;
}
