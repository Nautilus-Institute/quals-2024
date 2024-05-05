#include <pthread.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <queue>
#include <cassert>
#include <set>
#include <random>

#include <urcu/urcu-memb.h>	/* Userspace RCU flavor */
#include <urcu/rculist.h>	/* RCU list */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */
#include <urcu/rculfqueue.h>  /* RCU Lock-free queue */
#include <urcu/urcu.h>
#include <urcu/rculfhash.h>
#include <urcu/wfcqueue.h>
#include <urcu/rcuhlist.h>

#define PORT 8080
#define MAX_TRADE_HIST 30
#define MAX_CONNECTIONS 5
#define MAX_PASSWORD_ATTEMPTS 3
#define VIP_THRESHOLD_SILVER 100
#define VIP_THRESHOLD_GOLD 200
#define VIP_THRESHOLD_PLATINUM 300
using param_t = std::uniform_int_distribution<>::param_type;
class Session;

enum SortFunc {
  kTimeDec = 0,
  kTimeAsc = 1,
  kTickerDec = 2,
  kTickerAsc = 3,
  kSortMax = 4,
};

class Client {
  public:
    std::string m_username;
    std::string m_password;
    float m_balance;
    std::size_t m_hash;
    bool m_is_authd;
    bool m_is_vip;
    uint64_t m_num_trades;
    enum SortFunc m_sort_pref;
    Client();
    Client(std::string username, std::string password, float balance, uint64_t num_trades);
    std::string asString(char *indent="");
};

class ClientEntry : public Client {
  public:
    struct cds_hlist_node m_hlist_node; /* Linked-list chaining */
    struct rcu_head m_rcu_head; /* For call_rcu() */
    void *fuck;
    ClientEntry() {};
    ClientEntry(Client *client);
    std::string asString(char *indent);
};

class VipClientEntry : public ClientEntry {
  public:
    std::string m_vip_level;
    VipClientEntry(ClientEntry &entry);
    VipClientEntry(Client *client);
    std::string asString(char *indent);
    static std::string GetVipLevel(int num_trades) {
      assert(num_trades >= VIP_THRESHOLD_SILVER);
      if (num_trades >= VIP_THRESHOLD_PLATINUM)
        return std::string("Platinum");
      else if (num_trades >= VIP_THRESHOLD_GOLD)
        return std::string("Gold");
      else
       return std::string("Silver");
    };
};

enum ORDER_TYPE { BUY = 0, SELL = 1 };

struct Order {
  ORDER_TYPE m_type;
  struct cds_hlist_node m_hlist_node; /* Linked-list chaining */
  struct rcu_head m_rcu_head; /* For call_rcu() */
  std::string m_ticker;
  int64_t m_quantity;
  float m_price;
  //uint64_t m_timestamp;
  timespec m_timestamp;
  std::size_t m_client_hash;

  Order(ORDER_TYPE type, std::size_t hash);
  Order(ORDER_TYPE type, std::size_t hash, std::string ticker, int64_t quantity, float price);
  void setInfo(std::string m_ticker, int64_t quantity, float m_price);
  int getInfo(Session *s);
  std::string asString(char *indent="");

  bool operator < (const Order &o) const {
    assert(m_type == o.m_type);
    if (m_ticker != o.m_ticker) {
      return (m_ticker < o.m_ticker);
    }
    else if (m_price != o.m_price) {
      return (m_price < o.m_price);
    }
    else {
      if (m_timestamp.tv_sec != o.m_timestamp.tv_sec) {
        return (m_timestamp.tv_sec < o.m_timestamp.tv_sec);
      }
      else {
        return (m_timestamp.tv_nsec < o.m_timestamp.tv_nsec);
      }
    }
  }

  bool operator > (const Order &o) const {
    assert(m_type == o.m_type);
    if (m_ticker != o.m_ticker) {
      return (m_ticker < o.m_ticker);
    }
    else if (m_price != o.m_price) {
      return (m_price > o.m_price);
    }
    else {
      //return (m_timestamp < o.m_timestamp);
      if (m_timestamp.tv_sec != o.m_timestamp.tv_sec) {
        return (m_timestamp.tv_sec < o.m_timestamp.tv_sec);
      }
      else {
        return (m_timestamp.tv_nsec < o.m_timestamp.tv_nsec);
      }
    }
  }

};

struct Position {
  struct cds_list_head m_list_node;  /* Linked-list chaining */
  std::string m_ticker;
  std::size_t m_ticker_hash;
  std::size_t m_client_hash;
  int64_t m_quantity; // not uint for shorting

  Position(std::string ticker, int64_t quantity);
  std::string asString(char *indent="");
};

struct Trade {
  struct cds_list_head m_list_node; /* Linked-list chaining */
  struct rcu_head m_rcu_head; /* For call_rcu() */
  std::string m_ticker;
  std::size_t m_buyer_id;;
  std::size_t m_seller_id;;
  int64_t m_quantity;
  float m_price_per;
  float m_buyer_ask;
  float m_seller_ask;
  timespec m_timestamp;
  char padding[48+4];

  Trade(std::size_t buyer, std::size_t seller, std::string ticker, int64_t quantity, float price_per, float buyer_ask, float seller_ask);
  std::string asString(char *indent="");
};

template <typename T>
struct PointerGreater
{
    bool operator()(const T * lhs, const T * rhs) const
    {
        return *lhs > *rhs;
    }
};

template <typename T>
struct PointerLess
{
    bool operator()(const T * lhs, const T * rhs) const
    {
        return *lhs < *rhs;
    }
};

class TradeHistory {
  public:
    uint64_t m_hist_size;
    struct cds_list_head *m_first;
    CDS_LIST_HEAD(m_list_trades);
    TradeHistory(void);
    void listTrades(void);
    void addTrade(Trade *t);
};

// will contain a list of buy and sell orders
// as well as a list of matches that the matching engine will fill out
// MatchingEngine will pull from it
class OrderBook {
  public:
    CDS_HLIST_HEAD(m_hlist_buys);
    CDS_HLIST_HEAD(m_hlist_sells);

    std::multiset<Order *, PointerGreater<Order>> m_buys;
    std::multiset<Order *, PointerLess<Order>> m_sells;

    std::queue<Order *> m_orderq;
    pthread_mutex_t m_orderq_lock;
    pthread_cond_t m_orderq_cond;

    std::queue<Trade *> m_matchq;
    pthread_mutex_t m_matchq_lock;
    pthread_cond_t m_matchq_cond;

    TradeHistory *m_trade_history;
    OrderBook(void);
};

class PositionList {
  public:
    pthread_mutex_t m_list_lock;
    std::map<std::string, struct Position *> m_list;
    Position *getPosition(std::string ticker);
    int updatePosition(std::string ticker, int64_t delta);
    PositionList(void);
};

class PositionBook {
  public:
    pthread_mutex_t m_book_lock;
    std::map<std::size_t, PositionList *> m_book;
    PositionBook(void);
    struct cds_list_head *get(Client *client);
    void createNewPositionList(Client *client);
    int createOrUpdatePosition(std::size_t client_hash, std::string ticker, int64_t quantity);
    int updatePosition(std::size_t client_hash, std::string ticker, int64_t delta);
    PositionList *getPositionListForClient(std::size_t client_hash);
};

class TradingPlatform {
  public:
    OrderBook *m_orderbook;
    PositionBook *m_posbook;
    pthread_mutex_t m_client_map_lock;
    std::map<std::size_t, Client *> m_client_map;
    std::vector<std::string> m_tickers;
    int m_port;
    std::random_device m_rd;
    std::uniform_int_distribution<int> m_dist;
    std::string m_token;
    CDS_HLIST_HEAD(m_hlist_clients);
    CDS_HLIST_HEAD(m_hlist_vip_clients);

    // for a buy, check if the client has the funds
    // for a sell, check if the client has the quantity they are trying to sell
    bool isValidOrder(struct Order *order);
    void submitOrder(struct Order *order);
    void submitTrade(struct Trade *trade);
    Client *newAccount(Session *s);
    Client *newAccount(std::string username, std::string password, float balance, uint64_t num_trades);
    int login(Session *s);
    bool userExists(std::string username);
    Client *getClient(std::size_t hash);
    void startListen(void);
    void interact(int fd);
    void listOrders(Session *s);
    void listTrades(Session *s);
    void maybePromoteTrader(Client *client);
    void createEntryForClient(Client *client);
    ClientEntry *getClientEntryFromList(std::size_t hash);
    void ListClients(Session *s);

    TradingPlatform(std::string config_file, int port, char *token);
};

class MatchingEngine {
  public:
    TradingPlatform *m_platform;
    MatchingEngine(TradingPlatform *m_platform);
    void run(void);
    void match(void);
};

class TradingEngine {
  public:
    TradingPlatform *m_platform;
    TradingEngine(TradingPlatform *m_platform);
    void run(void);
    void execute(Trade *trade);
};

class Session {
  public:
    TradingPlatform *m_platform;
    Client *m_active_client;
    pthread_t m_tid;
    int m_fd;

    Session(TradingPlatform *platform, int fd);
    void interact(void);
    int recvUntil(void *buf, size_t n);
    int readInt();
    uint64_t readUint64();
    int64_t readInt64();
    float readFloat();
    int sendMsg(const char *msg);
    void run(void);
    int loggedIn(void);
    void setActiveClient(Client *client) {m_active_client = client; return;};
    Order *createOrder(ORDER_TYPE type);
    bool createBuyOrder(void);
    bool createSellOrder(void);
    void viewActiveAccount(void);
};
