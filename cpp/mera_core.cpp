// Mera / MLabChain v0.3
// Hybrid scientific-work monetary protocol reference node.
// Copyright 2026 Ali Bavarchee
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define BOOST_ERROR_CODE_HEADER_ONLY
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

using boost::multiprecision::uint128_t;
using boost::multiprecision::uint256_t;
using tcp = boost::asio::ip::tcp;

constexpr int PROTOCOL_VERSION = 3;
constexpr uint64_t ATOMIC_PER_MERA = 100000000ULL;
constexpr uint64_t MAX_SUPPLY = 100000000ULL * ATOMIC_PER_MERA;
constexpr uint64_t OPS_PER_MERA = 10000000ULL;
constexpr uint64_t MAX_WORK_REWARD = 50ULL * ATOMIC_PER_MERA;
constexpr uint64_t MIN_TX_FEE = 10000ULL;                 // 0.0001 MERA
constexpr uint64_t MIN_WORK_FEE = 100000ULL;             // 0.001 MERA
constexpr uint64_t CHALLENGE_BOND = 1000000ULL;          // 0.01 MERA
constexpr uint64_t MAX_CHALLENGE_BUDGET = 1000ULL * ATOMIC_PER_MERA;
constexpr uint64_t MIN_CHALLENGE_SAMPLES = 1000ULL;
constexpr uint64_t MAX_CHALLENGE_SAMPLES = 100000000ULL;
constexpr uint64_t MAX_BLOCK_TX = 2048ULL;
constexpr uint64_t MAX_MEMPOOL_TX = 20000ULL;
constexpr uint64_t MAX_PENDING_PER_SENDER = 32ULL;
constexpr uint64_t MAX_ACTIVE_CHALLENGES_PER_PROPOSER = 8ULL;
constexpr uint64_t MAX_TX_BYTES = 64ULL * 1024ULL;
constexpr uint64_t MAX_BLOCK_BYTES = 1ULL * 1024ULL * 1024ULL;
constexpr uint64_t MAX_NOTE_BYTES = 4096ULL;
constexpr uint64_t MAX_OPS_PER_WORK = 1000000000000000ULL;
constexpr uint64_t MAX_FUTURE_MS = 2ULL * 60ULL * 1000ULL;
constexpr uint64_t TARGET_BLOCK_MS = 60000ULL;
constexpr uint64_t DIFFICULTY_WINDOW = 16ULL;
constexpr int BASE_DIFFICULTY = 2;
constexpr int MIN_DIFFICULTY = 1;
constexpr int MAX_DIFFICULTY = 8;
constexpr uint64_t CHALLENGE_MATURITY = 8ULL;
constexpr uint64_t CHALLENGE_LIFETIME = 1000ULL;
constexpr uint64_t MAX_SIGNERS = 16ULL;
constexpr uint64_t GOVERNANCE_TIMELOCK = 32ULL;

const std::string NATIVE_VERIFIER = "MLabChain-linear-v4";

struct Tx {
    std::string txid;
    std::string type;
    std::string sender;
    std::string recipient;
    uint64_t amount = 0;
    uint64_t fee = 0;
    uint64_t nonce = 0;
    std::string challenge_id;
    std::string manifest_hash;
    std::string dataset_hash;
    std::string model_hash;
    std::string arch_hash;
    uint64_t ops = 0;
    uint64_t n_train = 0;
    uint64_t n_features = 0;
    uint64_t epochs = 0;
    uint64_t nmse_scaled = 0;
    uint64_t baseline_scaled = 0;
    uint64_t work_reward = 0;
    uint64_t wall_ms = 0;
    uint64_t lswu_micro = 0;
    std::string public_key;
    std::string signature;
    std::string payload_note;

    // Challenge-registration fields.
    uint64_t challenge_train_fraction_ppm = 0;
    uint64_t challenge_max_epochs = 0;
    uint64_t challenge_budget = 0;
    std::string challenge_verifier;
    std::string challenge_metric;
    std::string challenge_split_rule;

    // Key rotation.
    std::string new_public_key;

    // Native multisig authorization, encoded as comma-separated hex strings.
    uint64_t multisig_threshold = 0;
    std::string multisig_keys;
    std::string multisig_sigs;

    // Governance parameter schedule.
    std::string gov_key;
    std::string gov_value;
    uint64_t gov_effective_height = 0;
};

struct Block {
    uint64_t height = 0;
    uint64_t timestamp_ms = 0;
    std::string previous_hash;
    std::string merkle_root;
    int difficulty = 0;
    uint64_t nonce = 0;
    std::string producer;
    std::string producer_pubkey;
    std::string producer_signature;
    std::string block_hash;
    uint64_t total_ops = 0;
    uint64_t total_rewards = 0;
    uint256_t chain_work = 0;
    std::vector<Tx> transactions;
};

struct ChallengeState {
    std::string id;
    std::string manifest_hash;
    std::string dataset_hash;
    std::string verifier;
    std::string metric;
    std::string split_rule;
    uint64_t n_samples = 0;
    uint64_t n_features = 0;
    uint64_t train_fraction_ppm = 0;
    uint64_t max_epochs = 0;
    uint64_t baseline_scaled = 0;
    uint64_t created_height = 0;
    uint64_t activation_height = 0;
    uint64_t expiry_height = 0;
    uint64_t budget_remaining = 0;
    uint64_t best_quality_ppm = 0;
    std::string best_model_hash;
    std::string proposer;
};

struct AccountState {
    uint64_t balance = 0;
    uint64_t nonce = 0;
    std::string auth_pubkey;
};

struct Params {
    uint64_t min_fee = MIN_TX_FEE;
    uint64_t min_work_fee = MIN_WORK_FEE;
    uint64_t challenge_bond = CHALLENGE_BOND;
    uint64_t target_block_ms = TARGET_BLOCK_MS;
    uint64_t max_block_bytes = MAX_BLOCK_BYTES;
};

class DB {
public:
    sqlite3* db = nullptr;
    explicit DB(const std::string& path) {
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            std::string e = db ? sqlite3_errmsg(db) : "sqlite open failed";
            if (db) sqlite3_close(db);
            db = nullptr;
            throw std::runtime_error(e);
        }
        exec("PRAGMA journal_mode=WAL;");
        exec("PRAGMA foreign_keys=ON;");
        exec("PRAGMA synchronous=FULL;");
        exec("PRAGMA busy_timeout=5000;");
    }
    ~DB() { if (db) sqlite3_close(db); }
    void exec(const std::string& sql) {
        char* err = nullptr;
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            std::string e = err ? err : "unknown sqlite error";
            sqlite3_free(err);
            throw std::runtime_error("sqlite: " + e);
        }
    }
    sqlite3_stmt* prepare(const std::string& sql) const {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
            throw std::runtime_error("sqlite prepare: " + std::string(sqlite3_errmsg(db)));
        return st;
    }
    static void bind(sqlite3_stmt* st, int idx, const std::string& s) {
        sqlite3_bind_text(st, idx, s.c_str(), -1, SQLITE_TRANSIENT);
    }
    static void bind(sqlite3_stmt* st, int idx, uint64_t v) {
        if (v > static_cast<uint64_t>(std::numeric_limits<sqlite3_int64>::max()))
            throw std::runtime_error("integer exceeds SQLite signed 64-bit range");
        sqlite3_bind_int64(st, idx, static_cast<sqlite3_int64>(v));
    }
    static void bind(sqlite3_stmt* st, int idx, int v) { sqlite3_bind_int(st, idx, v); }
};

uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string network_name_default() { return "devnet"; }

std::string hex_bytes(const unsigned char* p, size_t n) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) out << std::setw(2) << static_cast<unsigned>(p[i]);
    return out.str();
}

std::vector<unsigned char> unhex(const std::string& s) {
    if (s.size() % 2) throw std::runtime_error("invalid hex length");
    std::vector<unsigned char> out(s.size() / 2);
    auto cvt=[](char c)->int{
        if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10; return -1;
    };
    for(size_t i=0;i<out.size();++i){int a=cvt(s[2*i]),b=cvt(s[2*i+1]);if(a<0||b<0)throw std::runtime_error("invalid hex");out[i]=static_cast<unsigned char>((a<<4)|b);} return out;
}

std::string hex_encode_text(const std::string& s) {
    return hex_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}
std::string hex_decode_text(const std::string& s) {
    auto v=unhex(s); return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

std::string sha256(std::string_view data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return hex_bytes(digest, SHA256_DIGEST_LENGTH);
}

std::string checksum_for(const std::string& prefix_payload) { return sha256("MERA-ADDR-V3|" + prefix_payload).substr(0,8); }

std::string address_from_pubkey(const std::string& pub_hex) {
    auto p=unhex(pub_hex); if(p.size()!=32) throw std::runtime_error("Ed25519 public key must be 32 bytes");
    std::string payload=sha256(std::string(reinterpret_cast<const char*>(p.data()),p.size())).substr(0,40);
    return "MERA1"+payload+checksum_for("MERA1"+payload);
}

bool valid_address(const std::string& address) {
    if(address.size()!=53) return false;
    if(address.rfind("MERA1",0)!=0 && address.rfind("MERA2",0)!=0) return false;
    std::string payload=address.substr(0,45), ck=address.substr(45);
    try { (void)unhex(address.substr(5,40)); (void)unhex(address.substr(45,8)); } catch(...) { return false; }
    return checksum_for(payload)==ck;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out; std::string cur;
    for(char c:s){if(c==sep){out.push_back(cur);cur.clear();}else cur.push_back(c);} out.push_back(cur); return out;
}
std::string join(const std::vector<std::string>& xs, const std::string& sep) {
    std::ostringstream o; for(size_t i=0;i<xs.size();++i){if(i)o<<sep;o<<xs[i];} return o.str();
}

std::vector<std::string> signer_keys(const Tx& t) { return split(t.multisig_keys, ','); }
std::vector<std::string> signer_sigs(const Tx& t) { return split(t.multisig_sigs, ','); }

std::string multisig_address(uint64_t threshold, std::vector<std::string> keys) {
    if(threshold==0||threshold>keys.size()||keys.size()>MAX_SIGNERS) throw std::runtime_error("invalid multisig threshold");
    for(auto &k:keys){if(unhex(k).size()!=32)throw std::runtime_error("invalid multisig public key");}
    std::sort(keys.begin(),keys.end());
    std::string material="MSIG|"+std::to_string(threshold)+"|"+join(keys,",");
    std::string payload=sha256(material).substr(0,40);
    return "MERA2"+payload+checksum_for("MERA2"+payload);
}

bool verify_ed25519(const std::string& pub_hex,const std::string& message,const std::string& sig_hex){
    try{
        auto pub=unhex(pub_hex),sig=unhex(sig_hex);if(pub.size()!=32||sig.size()!=64)return false;
        EVP_PKEY* key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,pub.data(),pub.size());if(!key)return false;
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();bool ok=false;
        if(ctx && EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1)
            ok=EVP_DigestVerify(ctx,sig.data(),sig.size(),reinterpret_cast<const unsigned char*>(message.data()),message.size())==1;
        if(ctx)EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);return ok;
    }catch(...){return false;}
}

uint64_t u64(const std::string&s){size_t p=0;unsigned long long x=std::stoull(s,&p,10);if(p!=s.size())throw std::runtime_error("invalid unsigned integer: "+s);return static_cast<uint64_t>(x);}
std::string req(const std::map<std::string,std::string>&a,const std::string&k){auto i=a.find(k);if(i==a.end())throw std::runtime_error("missing --"+k);return i->second;}
std::string opt(const std::map<std::string,std::string>&a,const std::string&k,const std::string&d=""){auto i=a.find(k);return i==a.end()?d:i->second;}
std::map<std::string,std::string> args_map(int argc,char**argv,int start=2){std::map<std::string,std::string>a;for(int i=start;i<argc;++i){std::string k=argv[i];if(k.rfind("--",0)!=0)throw std::runtime_error("expected --key");k=k.substr(2);if(i+1>=argc||std::string(argv[i+1]).rfind("--",0)==0)a[k]="true";else a[k]=argv[++i];}return a;}

std::string transfer_message(const Tx&t){return "TRANSFER-V3|"+t.sender+"|"+t.recipient+"|"+std::to_string(t.amount)+"|"+std::to_string(t.fee)+"|"+std::to_string(t.nonce)+"|"+t.public_key+"|"+t.payload_note;}
std::string multisig_transfer_message(const Tx&t){return "MULTISIG_TRANSFER-V3|"+t.sender+"|"+t.recipient+"|"+std::to_string(t.amount)+"|"+std::to_string(t.fee)+"|"+std::to_string(t.nonce)+"|"+std::to_string(t.multisig_threshold)+"|"+t.multisig_keys+"|"+t.payload_note;}
std::string ml_message(const Tx&t){return "ML_WORK-V3|"+t.sender+"|"+t.challenge_id+"|"+t.manifest_hash+"|"+t.dataset_hash+"|"+t.model_hash+"|"+t.arch_hash+"|"+std::to_string(t.ops)+"|"+std::to_string(t.n_train)+"|"+std::to_string(t.n_features)+"|"+std::to_string(t.epochs)+"|"+std::to_string(t.nmse_scaled)+"|"+std::to_string(t.baseline_scaled)+"|"+std::to_string(t.work_reward)+"|"+std::to_string(t.wall_ms)+"|"+std::to_string(t.lswu_micro)+"|"+std::to_string(t.nonce)+"|"+std::to_string(t.fee)+"|"+t.public_key+"|"+t.payload_note;}
std::string challenge_message(const Tx&t){return "CHALLENGE_REGISTER-V3|"+t.sender+"|"+t.challenge_id+"|"+t.manifest_hash+"|"+t.dataset_hash+"|"+t.challenge_verifier+"|"+t.challenge_metric+"|"+t.challenge_split_rule+"|"+std::to_string(t.n_train)+"|"+std::to_string(t.n_features)+"|"+std::to_string(t.challenge_train_fraction_ppm)+"|"+std::to_string(t.challenge_max_epochs)+"|"+std::to_string(t.baseline_scaled)+"|"+std::to_string(t.challenge_budget)+"|"+std::to_string(t.nonce)+"|"+std::to_string(t.fee)+"|"+t.public_key;}
std::string key_rotate_message(const Tx&t){return "KEY_ROTATE-V3|"+t.sender+"|"+t.new_public_key+"|"+std::to_string(t.nonce)+"|"+t.public_key;}
std::string gov_message(const Tx&t){return "GOV_PARAM-V3|"+t.sender+"|"+t.gov_key+"|"+t.gov_value+"|"+std::to_string(t.gov_effective_height)+"|"+std::to_string(t.nonce)+"|"+std::to_string(t.multisig_threshold)+"|"+t.multisig_keys;}

std::string txid(const Tx&t){
    std::string m;
    if(t.type=="TRANSFER")m=transfer_message(t);
    else if(t.type=="MULTISIG_TRANSFER")m=multisig_transfer_message(t);
    else if(t.type=="ML_WORK")m=ml_message(t);
    else if(t.type=="CHALLENGE_REGISTER")m=challenge_message(t);
    else if(t.type=="KEY_ROTATE")m=key_rotate_message(t);
    else if(t.type=="GOV_PARAM")m=gov_message(t);
    else if(t.type=="FAUCET")m="FAUCET-V3|"+t.recipient+"|"+std::to_string(t.amount);
    else throw std::runtime_error("unknown tx type");
    return sha256(m+"|"+t.signature+"|"+t.multisig_sigs);
}

uint64_t quality_ppm(const Tx&t){if(!t.baseline_scaled||t.nmse_scaled>=t.baseline_scaled)return 0;uint128_t n=uint128_t(t.baseline_scaled-t.nmse_scaled)*1000000;return std::min<uint64_t>(static_cast<uint64_t>(n/t.baseline_scaled),1000000ULL);}
uint64_t work_reward_for_quality(uint64_t ops,uint64_t delta_q){uint128_t n=uint128_t(ops)*delta_q*ATOMIC_PER_MERA;uint64_t r=static_cast<uint64_t>(n/(uint128_t(OPS_PER_MERA)*1000000));return std::min(r,MAX_WORK_REWARD);}
uint256_t pow_work(int d){return uint256_t(1) << (4*d);}
uint64_t median_time_past(const std::vector<Block>& chain){
    if(chain.empty()) return 0;
    size_t begin=chain.size()>11?chain.size()-11:0;
    std::vector<uint64_t> ts; for(size_t i=begin;i<chain.size();++i) ts.push_back(chain[i].timestamp_ms);
    std::sort(ts.begin(),ts.end()); return ts[ts.size()/2];
}
uint64_t checked_work_ops(uint64_t epochs,uint64_t n_train,uint64_t n_features){
    uint128_t total=uint128_t(epochs)*n_train*(uint128_t(3)*n_features+4);
    if(total>MAX_OPS_PER_WORK) throw std::runtime_error("symbolic operation count exceeds protocol limit");
    return static_cast<uint64_t>(total);
}

std::string tx_wire(const Tx&t){
    std::vector<std::string> f={
        t.type,t.sender,t.recipient,std::to_string(t.amount),std::to_string(t.fee),std::to_string(t.nonce),
        t.challenge_id,t.manifest_hash,t.dataset_hash,t.model_hash,t.arch_hash,std::to_string(t.ops),
        std::to_string(t.n_train),std::to_string(t.n_features),std::to_string(t.epochs),std::to_string(t.nmse_scaled),
        std::to_string(t.baseline_scaled),std::to_string(t.work_reward),std::to_string(t.wall_ms),std::to_string(t.lswu_micro),
        t.public_key,t.signature,t.payload_note,std::to_string(t.challenge_train_fraction_ppm),std::to_string(t.challenge_max_epochs),
        std::to_string(t.challenge_budget),t.challenge_verifier,t.challenge_metric,t.challenge_split_rule,t.new_public_key,
        std::to_string(t.multisig_threshold),t.multisig_keys,t.multisig_sigs,t.gov_key,t.gov_value,std::to_string(t.gov_effective_height)};
    for(auto &x:f)x=hex_encode_text(x);
    return join(f,"|");
}
Tx tx_from_wire(const std::string&w){
    auto f=split(w,'|');if(f.size()!=36)throw std::runtime_error("malformed tx wire");for(auto &x:f)x=hex_decode_text(x);Tx t;size_t i=0;
    t.type=f[i++];t.sender=f[i++];t.recipient=f[i++];t.amount=u64(f[i++]);t.fee=u64(f[i++]);t.nonce=u64(f[i++]);t.challenge_id=f[i++];t.manifest_hash=f[i++];t.dataset_hash=f[i++];t.model_hash=f[i++];t.arch_hash=f[i++];t.ops=u64(f[i++]);t.n_train=u64(f[i++]);t.n_features=u64(f[i++]);t.epochs=u64(f[i++]);t.nmse_scaled=u64(f[i++]);t.baseline_scaled=u64(f[i++]);t.work_reward=u64(f[i++]);t.wall_ms=u64(f[i++]);t.lswu_micro=u64(f[i++]);t.public_key=f[i++];t.signature=f[i++];t.payload_note=f[i++];t.challenge_train_fraction_ppm=u64(f[i++]);t.challenge_max_epochs=u64(f[i++]);t.challenge_budget=u64(f[i++]);t.challenge_verifier=f[i++];t.challenge_metric=f[i++];t.challenge_split_rule=f[i++];t.new_public_key=f[i++];t.multisig_threshold=u64(f[i++]);t.multisig_keys=f[i++];t.multisig_sigs=f[i++];t.gov_key=f[i++];t.gov_value=f[i++];t.gov_effective_height=u64(f[i++]);t.txid=txid(t);return t;
}

std::string merkle_root(const std::vector<Tx>&txs){if(txs.empty())return sha256("EMPTY");std::vector<std::string>h;for(auto &t:txs)h.push_back(sha256("L"+txid(t)));while(h.size()>1){if(h.size()%2)h.push_back(h.back());std::vector<std::string>n;for(size_t i=0;i<h.size();i+=2)n.push_back(sha256("N"+h[i]+h[i+1]));h.swap(n);}return h[0];}

std::string block_header(const Block&b){
    return "MERA-BLOCK-V3|"+std::to_string(b.height)+"|"+std::to_string(b.timestamp_ms)+"|"+b.previous_hash+"|"+
           b.merkle_root+"|"+std::to_string(b.difficulty)+"|"+std::to_string(b.nonce)+"|"+b.producer+"|"+
           b.producer_pubkey+"|"+b.producer_signature+"|"+std::to_string(b.total_ops)+"|"+std::to_string(b.total_rewards);
}
std::string block_signing_message(const Block&b){
    return "MERA-BLOCK-PROPOSAL-V3|"+std::to_string(b.height)+"|"+std::to_string(b.timestamp_ms)+"|"+b.previous_hash+"|"+
           b.merkle_root+"|"+std::to_string(b.difficulty)+"|"+b.producer+"|"+b.producer_pubkey+"|"+std::to_string(b.total_ops)+"|"+std::to_string(b.total_rewards);
}
std::string mine_hash(Block&b){std::string target(static_cast<size_t>(b.difficulty),'0');for(b.nonce=0;;++b.nonce){std::string h=sha256(block_header(b));if(h.rfind(target,0)==0)return h;if(b.nonce==std::numeric_limits<uint64_t>::max())throw std::runtime_error("nonce exhausted");}}

uint64_t tx_size(const Tx&t){return static_cast<uint64_t>(tx_wire(t).size());}
uint64_t block_size(const Block&b){uint64_t n=static_cast<uint64_t>(block_header(b).size()+128);for(auto &t:b.transactions)n+=tx_size(t)+8;return n;}

class Replay {
public:
    std::map<std::string,AccountState> accounts;
    std::map<std::string,ChallengeState> challenges;
    std::set<std::string> work_claims;
    uint64_t supply=0;
    Params params;
    std::map<std::string,std::pair<uint64_t,uint64_t>> scheduled_params;

    AccountState& acct(const std::string&a){return accounts[a];}
    uint64_t balance(const std::string&a) const {auto i=accounts.find(a);return i==accounts.end()?0:i->second.balance;}
    uint64_t nonce(const std::string&a) const {auto i=accounts.find(a);return i==accounts.end()?0:i->second.nonce;}
    void activate(uint64_t height){for(auto i=scheduled_params.begin();i!=scheduled_params.end();){if(i->second.first<=height){if(i->first=="min_fee")params.min_fee=i->second.second;else if(i->first=="min_work_fee")params.min_work_fee=i->second.second;else if(i->first=="challenge_bond")params.challenge_bond=i->second.second;else if(i->first=="target_block_ms")params.target_block_ms=i->second.second;else if(i->first=="max_block_bytes")params.max_block_bytes=i->second.second;i=scheduled_params.erase(i);}else ++i;}}
};


class State {
public:
    DB db;
    std::string db_path;
    std::string network;
    Params genesis_params() const { Params p; if(network=="devnet"){p.min_fee=1000;p.min_work_fee=10000;p.challenge_bond=100000;} return p; }

    explicit State(const std::string&path,const std::string&requested_network="",const std::string&genesis_gov_keys="",uint64_t genesis_gov_threshold=0):db(path),db_path(path){init_schema();ensure_genesis(requested_network,genesis_gov_keys,genesis_gov_threshold);network=meta("network");ensure_migrations();}

    void init_schema(){
        db.exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);");
        std::string existing_schema=meta("schema_version");
        if(!existing_schema.empty() && existing_schema!=std::to_string(PROTOCOL_VERSION))
            throw std::runtime_error("unsupported database schema "+existing_schema+"; export with tools/migrate_v2.py before opening with v3");
        db.exec("CREATE TABLE IF NOT EXISTS accounts(address TEXT PRIMARY KEY,balance INTEGER NOT NULL,nonce INTEGER NOT NULL,auth_pubkey TEXT NOT NULL DEFAULT '');");
        db.exec("CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY,timestamp_ms INTEGER NOT NULL,previous_hash TEXT NOT NULL,merkle_root TEXT NOT NULL,difficulty INTEGER NOT NULL,nonce INTEGER NOT NULL,producer TEXT NOT NULL,producer_pubkey TEXT NOT NULL DEFAULT '',producer_signature TEXT NOT NULL DEFAULT '',block_hash TEXT NOT NULL UNIQUE,total_ops INTEGER NOT NULL,total_rewards INTEGER NOT NULL,chain_work TEXT NOT NULL DEFAULT '0');");
        db.exec("CREATE TABLE IF NOT EXISTS txs(txid TEXT PRIMARY KEY,height INTEGER NOT NULL,ord INTEGER NOT NULL,type TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,amount INTEGER NOT NULL,fee INTEGER NOT NULL,nonce INTEGER NOT NULL,challenge_id TEXT NOT NULL,manifest_hash TEXT NOT NULL,dataset_hash TEXT NOT NULL,model_hash TEXT NOT NULL,arch_hash TEXT NOT NULL,ops INTEGER NOT NULL,n_train INTEGER NOT NULL,n_features INTEGER NOT NULL,epochs INTEGER NOT NULL,nmse_scaled INTEGER NOT NULL,baseline_scaled INTEGER NOT NULL,work_reward INTEGER NOT NULL,wall_ms INTEGER NOT NULL,lswu_micro INTEGER NOT NULL,public_key TEXT NOT NULL,signature TEXT NOT NULL,payload_note TEXT NOT NULL,challenge_train_fraction_ppm INTEGER NOT NULL DEFAULT 0,challenge_max_epochs INTEGER NOT NULL DEFAULT 0,challenge_budget INTEGER NOT NULL DEFAULT 0,challenge_verifier TEXT NOT NULL DEFAULT '',challenge_metric TEXT NOT NULL DEFAULT '',challenge_split_rule TEXT NOT NULL DEFAULT '',new_public_key TEXT NOT NULL DEFAULT '',multisig_threshold INTEGER NOT NULL DEFAULT 0,multisig_keys TEXT NOT NULL DEFAULT '',multisig_sigs TEXT NOT NULL DEFAULT '',gov_key TEXT NOT NULL DEFAULT '',gov_value TEXT NOT NULL DEFAULT '',gov_effective_height INTEGER NOT NULL DEFAULT 0);");
        db.exec("CREATE TABLE IF NOT EXISTS pending(seq INTEGER PRIMARY KEY AUTOINCREMENT,txid TEXT UNIQUE NOT NULL,type TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,amount INTEGER NOT NULL,fee INTEGER NOT NULL,nonce INTEGER NOT NULL,challenge_id TEXT NOT NULL,manifest_hash TEXT NOT NULL,dataset_hash TEXT NOT NULL,model_hash TEXT NOT NULL,arch_hash TEXT NOT NULL,ops INTEGER NOT NULL,n_train INTEGER NOT NULL,n_features INTEGER NOT NULL,epochs INTEGER NOT NULL,nmse_scaled INTEGER NOT NULL,baseline_scaled INTEGER NOT NULL,work_reward INTEGER NOT NULL,wall_ms INTEGER NOT NULL,lswu_micro INTEGER NOT NULL,public_key TEXT NOT NULL,signature TEXT NOT NULL,payload_note TEXT NOT NULL,challenge_train_fraction_ppm INTEGER NOT NULL DEFAULT 0,challenge_max_epochs INTEGER NOT NULL DEFAULT 0,challenge_budget INTEGER NOT NULL DEFAULT 0,challenge_verifier TEXT NOT NULL DEFAULT '',challenge_metric TEXT NOT NULL DEFAULT '',challenge_split_rule TEXT NOT NULL DEFAULT '',new_public_key TEXT NOT NULL DEFAULT '',multisig_threshold INTEGER NOT NULL DEFAULT 0,multisig_keys TEXT NOT NULL DEFAULT '',multisig_sigs TEXT NOT NULL DEFAULT '',gov_key TEXT NOT NULL DEFAULT '',gov_value TEXT NOT NULL DEFAULT '',gov_effective_height INTEGER NOT NULL DEFAULT 0);");
        db.exec("CREATE TABLE IF NOT EXISTS challenges(challenge_id TEXT PRIMARY KEY,manifest_hash TEXT NOT NULL,dataset_hash TEXT NOT NULL,verifier TEXT NOT NULL,metric TEXT NOT NULL,split_rule TEXT NOT NULL,n_samples INTEGER NOT NULL,n_features INTEGER NOT NULL,train_fraction_ppm INTEGER NOT NULL,max_epochs INTEGER NOT NULL,baseline_scaled INTEGER NOT NULL,created_height INTEGER NOT NULL,activation_height INTEGER NOT NULL,expiry_height INTEGER NOT NULL,budget_remaining INTEGER NOT NULL,best_quality_ppm INTEGER NOT NULL,best_model_hash TEXT NOT NULL,proposer TEXT NOT NULL);");
        db.exec("CREATE TABLE IF NOT EXISTS work_claims(challenge_id TEXT NOT NULL,dataset_hash TEXT NOT NULL,model_hash TEXT NOT NULL,txid TEXT NOT NULL,height INTEGER NOT NULL,PRIMARY KEY(challenge_id,dataset_hash,model_hash));");
        db.exec("CREATE TABLE IF NOT EXISTS gov_updates(param_key TEXT PRIMARY KEY,param_value INTEGER NOT NULL,effective_height INTEGER NOT NULL,txid TEXT NOT NULL);");
        db.exec("CREATE INDEX IF NOT EXISTS idx_pending_sender_nonce ON pending(sender,nonce);");
        db.exec("CREATE INDEX IF NOT EXISTS idx_pending_fee ON pending(fee DESC,seq ASC);");
        db.exec("CREATE INDEX IF NOT EXISTS idx_txs_height_ord ON txs(height,ord);");
        db.exec("CREATE INDEX IF NOT EXISTS idx_txs_sender_nonce ON txs(sender,nonce);");
        db.exec("CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);");
    }

    void ensure_genesis(const std::string&requested,const std::string&gov_keys="",uint64_t gov_threshold=0){
        std::string existing=meta("network");
        std::string wanted=requested.empty()?network_name_default():requested;
        if(!existing.empty()){
            if(!requested.empty() && existing!=requested)throw std::runtime_error("network mismatch: database="+existing+" requested="+requested);
            if(!gov_keys.empty() && meta("governance_keys")!=([&]{auto g=split(gov_keys,',');std::sort(g.begin(),g.end());return join(g,",");})()) throw std::runtime_error("governance genesis keys mismatch");
            return;
        }
        if(wanted!="devnet"&&wanted!="testnet"&&wanted!="mainnet")throw std::runtime_error("network must be devnet, testnet, or mainnet");
        set_meta("schema_version",std::to_string(PROTOCOL_VERSION));set_meta("protocol_version",std::to_string(PROTOCOL_VERSION));set_meta("network",wanted);set_meta("asset","MERA");set_meta("decimals","8");set_meta("max_supply",std::to_string(MAX_SUPPLY));set_meta("faucet_enabled",wanted=="devnet"?"1":"0");
        std::string canon_gov=""; if(!gov_keys.empty()){auto g=split(gov_keys,',');std::sort(g.begin(),g.end());if(gov_threshold==0||gov_threshold>g.size()||g.size()>MAX_SIGNERS)throw std::runtime_error("invalid governance genesis signer set");canon_gov=join(g,",");} set_meta("genesis_hash",sha256("MERA-GENESIS-V3|"+wanted+"|GOV|"+canon_gov+"|TH|"+std::to_string(gov_threshold)));set_meta("total_supply","0");
        Params p; if(wanted=="devnet"){p.min_fee=1000;p.min_work_fee=10000;p.challenge_bond=100000;} else if(wanted=="testnet"){p.min_fee=10000;p.min_work_fee=100000;p.challenge_bond=1000000;}
        set_param_meta(p);
        if(canon_gov.empty()){set_meta("governance_keys", ""); set_meta("governance_threshold", "0"); set_meta("governance_address", "");} else {set_meta("governance_keys",canon_gov);set_meta("governance_threshold",std::to_string(gov_threshold));set_meta("governance_address",multisig_address(gov_threshold,split(canon_gov,',')));}
        Block g;g.height=0;g.timestamp_ms=0;g.previous_hash=std::string(64,'0');g.merkle_root=sha256("GENESIS-V3|"+wanted);g.difficulty=0;g.nonce=0;g.producer="GENESIS";g.block_hash=sha256(block_header(g));g.chain_work=0;
        insert_block_header(g);
    }
    void ensure_migrations(){if(meta("schema_version")!=std::to_string(PROTOCOL_VERSION))throw std::runtime_error("unsupported database schema; run tools/migrate_v2.py to create a v3 snapshot");}

    std::string meta(const std::string&k,const std::string&d="") const {auto st=db.prepare("SELECT v FROM meta WHERE k=?");DB::bind(st,1,k);std::string v=d;if(sqlite3_step(st)==SQLITE_ROW)v=reinterpret_cast<const char*>(sqlite3_column_text(st,0));sqlite3_finalize(st);return v;}
    void set_meta(const std::string&k,const std::string&v){auto st=db.prepare("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v");DB::bind(st,1,k);DB::bind(st,2,v);if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error(e);}sqlite3_finalize(st);}
    Params params() const {Params p;p.min_fee=u64(meta("min_fee",std::to_string(MIN_TX_FEE)));p.min_work_fee=u64(meta("min_work_fee",std::to_string(MIN_WORK_FEE)));p.challenge_bond=u64(meta("challenge_bond",std::to_string(CHALLENGE_BOND)));p.target_block_ms=u64(meta("target_block_ms",std::to_string(TARGET_BLOCK_MS)));p.max_block_bytes=u64(meta("max_block_bytes",std::to_string(MAX_BLOCK_BYTES)));return p;}
    void set_param_meta(const Params&p){set_meta("min_fee",std::to_string(p.min_fee));set_meta("min_work_fee",std::to_string(p.min_work_fee));set_meta("challenge_bond",std::to_string(p.challenge_bond));set_meta("target_block_ms",std::to_string(p.target_block_ms));set_meta("max_block_bytes",std::to_string(p.max_block_bytes));}

    void configure_governance(const std::string&keys_csv, uint64_t threshold){
        if(height()!=0) throw std::runtime_error("governance can only be configured at genesis");
        auto ks=split(keys_csv, ','); if(threshold==0||threshold>ks.size()||ks.size()>MAX_SIGNERS) throw std::runtime_error("invalid governance signer set");
        std::sort(ks.begin(),ks.end());
        std::string addr=multisig_address(threshold,ks);
        std::string existing=meta("governance_keys");
        if(!existing.empty() && existing!=join(ks,",")) throw std::runtime_error("governance signer set already initialized");
        set_meta("governance_keys",join(ks,",")); set_meta("governance_threshold",std::to_string(threshold)); set_meta("governance_address",addr);
    }

    void insert_block_header(const Block&b){auto st=db.prepare("INSERT INTO blocks(height,timestamp_ms,previous_hash,merkle_root,difficulty,nonce,producer,producer_pubkey,producer_signature,block_hash,total_ops,total_rewards,chain_work) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");int i=1;DB::bind(st,i++,b.height);DB::bind(st,i++,b.timestamp_ms);DB::bind(st,i++,b.previous_hash);DB::bind(st,i++,b.merkle_root);DB::bind(st,i++,b.difficulty);DB::bind(st,i++,b.nonce);DB::bind(st,i++,b.producer);DB::bind(st,i++,b.producer_pubkey);DB::bind(st,i++,b.producer_signature);DB::bind(st,i++,b.block_hash);DB::bind(st,i++,b.total_ops);DB::bind(st,i++,b.total_rewards);DB::bind(st,i++,b.chain_work.convert_to<std::string>());if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error(e);}sqlite3_finalize(st);}

    AccountState account(const std::string&a) const {auto st=db.prepare("SELECT balance,nonce,auth_pubkey FROM accounts WHERE address=?");DB::bind(st,1,a);AccountState x;if(sqlite3_step(st)==SQLITE_ROW){x.balance=static_cast<uint64_t>(sqlite3_column_int64(st,0));x.nonce=static_cast<uint64_t>(sqlite3_column_int64(st,1));auto p=sqlite3_column_text(st,2);x.auth_pubkey=p?reinterpret_cast<const char*>(p):"";}sqlite3_finalize(st);return x;}
    void set_account(const std::string&a,const AccountState&x){auto st=db.prepare("INSERT INTO accounts(address,balance,nonce,auth_pubkey) VALUES(?,?,?,?) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance,nonce=excluded.nonce,auth_pubkey=excluded.auth_pubkey");DB::bind(st,1,a);DB::bind(st,2,x.balance);DB::bind(st,3,x.nonce);DB::bind(st,4,x.auth_pubkey);if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error(e);}sqlite3_finalize(st);}
    uint64_t balance(const std::string&a) const {return account(a).balance;}
    uint64_t nonce(const std::string&a) const {return account(a).nonce;}
    uint64_t total_supply() const {return u64(meta("total_supply", "0"));}
    void set_supply(uint64_t x){if(x>MAX_SUPPLY)throw std::runtime_error("supply exceeds cap");set_meta("total_supply",std::to_string(x));}
    uint64_t height() const {auto st=db.prepare("SELECT MAX(height) FROM blocks");uint64_t h=0;if(sqlite3_step(st)==SQLITE_ROW)h=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);return h;}
    Block load_block(uint64_t h) const {auto st=db.prepare("SELECT height,timestamp_ms,previous_hash,merkle_root,difficulty,nonce,producer,producer_pubkey,producer_signature,block_hash,total_ops,total_rewards,chain_work FROM blocks WHERE height=?");DB::bind(st,1,h);if(sqlite3_step(st)!=SQLITE_ROW){sqlite3_finalize(st);throw std::runtime_error("block not found");}Block b;int c=0;b.height=static_cast<uint64_t>(sqlite3_column_int64(st,c++));b.timestamp_ms=static_cast<uint64_t>(sqlite3_column_int64(st,c++));b.previous_hash=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.merkle_root=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.difficulty=sqlite3_column_int(st,c++);b.nonce=static_cast<uint64_t>(sqlite3_column_int64(st,c++));b.producer=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.producer_pubkey=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.producer_signature=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.block_hash=reinterpret_cast<const char*>(sqlite3_column_text(st,c++));b.total_ops=static_cast<uint64_t>(sqlite3_column_int64(st,c++));b.total_rewards=static_cast<uint64_t>(sqlite3_column_int64(st,c++));b.chain_work=uint256_t(reinterpret_cast<const char*>(sqlite3_column_text(st,c++)));sqlite3_finalize(st);load_txs(b);return b;}
    void load_txs(Block&b) const {auto st=db.prepare("SELECT type,sender,recipient,amount,fee,nonce,challenge_id,manifest_hash,dataset_hash,model_hash,arch_hash,ops,n_train,n_features,epochs,nmse_scaled,baseline_scaled,work_reward,wall_ms,lswu_micro,public_key,signature,payload_note,challenge_train_fraction_ppm,challenge_max_epochs,challenge_budget,challenge_verifier,challenge_metric,challenge_split_rule,new_public_key,multisig_threshold,multisig_keys,multisig_sigs,gov_key,gov_value,gov_effective_height,txid FROM txs WHERE height=? ORDER BY ord");DB::bind(st,1,b.height);while(sqlite3_step(st)==SQLITE_ROW){Tx t;int c=0;auto ct=[&](){auto p=sqlite3_column_text(st,c++);return p?std::string(reinterpret_cast<const char*>(p)):std::string();};auto cu=[&](){return static_cast<uint64_t>(sqlite3_column_int64(st,c++));};t.type=ct();t.sender=ct();t.recipient=ct();t.amount=cu();t.fee=cu();t.nonce=cu();t.challenge_id=ct();t.manifest_hash=ct();t.dataset_hash=ct();t.model_hash=ct();t.arch_hash=ct();t.ops=cu();t.n_train=cu();t.n_features=cu();t.epochs=cu();t.nmse_scaled=cu();t.baseline_scaled=cu();t.work_reward=cu();t.wall_ms=cu();t.lswu_micro=cu();t.public_key=ct();t.signature=ct();t.payload_note=ct();t.challenge_train_fraction_ppm=cu();t.challenge_max_epochs=cu();t.challenge_budget=cu();t.challenge_verifier=ct();t.challenge_metric=ct();t.challenge_split_rule=ct();t.new_public_key=ct();t.multisig_threshold=cu();t.multisig_keys=ct();t.multisig_sigs=ct();t.gov_key=ct();t.gov_value=ct();t.gov_effective_height=cu();t.txid=ct();b.transactions.push_back(t);}sqlite3_finalize(st);}
    std::string tip_hash() const {return load_block(height()).block_hash;}

    ChallengeState load_challenge(const std::string&id) const {auto st=db.prepare("SELECT challenge_id,manifest_hash,dataset_hash,verifier,metric,split_rule,n_samples,n_features,train_fraction_ppm,max_epochs,baseline_scaled,created_height,activation_height,expiry_height,budget_remaining,best_quality_ppm,best_model_hash,proposer FROM challenges WHERE challenge_id=?");DB::bind(st,1,id);if(sqlite3_step(st)!=SQLITE_ROW){sqlite3_finalize(st);throw std::runtime_error("challenge not found");}ChallengeState c;int x=0;auto ct=[&](){auto p=sqlite3_column_text(st,x++);return p?std::string(reinterpret_cast<const char*>(p)):std::string();};auto cu=[&](){return static_cast<uint64_t>(sqlite3_column_int64(st,x++));};c.id=ct();c.manifest_hash=ct();c.dataset_hash=ct();c.verifier=ct();c.metric=ct();c.split_rule=ct();c.n_samples=cu();c.n_features=cu();c.train_fraction_ppm=cu();c.max_epochs=cu();c.baseline_scaled=cu();c.created_height=cu();c.activation_height=cu();c.expiry_height=cu();c.budget_remaining=cu();c.best_quality_ppm=cu();c.best_model_hash=ct();c.proposer=ct();sqlite3_finalize(st);return c;}
    void print_challenge(const std::string&id) const {auto c=load_challenge(id);std::cout<<"CHALLENGE_ID="<<c.id<<"\nMANIFEST_SHA256="<<c.manifest_hash<<"\nDATASET_SHA256="<<c.dataset_hash<<"\nVERIFIER="<<c.verifier<<"\nMETRIC="<<c.metric<<"\nSPLIT_RULE="<<c.split_rule<<"\nN_SAMPLES="<<c.n_samples<<"\nN_FEATURES="<<c.n_features<<"\nTRAIN_FRACTION_PPM="<<c.train_fraction_ppm<<"\nMAX_EPOCHS="<<c.max_epochs<<"\nACTIVATION_HEIGHT="<<c.activation_height<<"\nEXPIRY_HEIGHT="<<c.expiry_height<<"\nBUDGET_REMAINING_ATOMIC="<<c.budget_remaining<<"\nBEST_QUALITY_PPM="<<c.best_quality_ppm<<"\nBEST_MODEL_SHA256="<<c.best_model_hash<<"\nPROPOSER="<<c.proposer<<"\n";}
    bool challenge_exists(const std::string&id) const {auto st=db.prepare("SELECT 1 FROM challenges WHERE challenge_id=?");DB::bind(st,1,id);bool ok=sqlite3_step(st)==SQLITE_ROW;sqlite3_finalize(st);return ok;}
    bool work_claim_exists(const Tx&t) const {auto st=db.prepare("SELECT 1 FROM work_claims WHERE challenge_id=? AND dataset_hash=? AND model_hash=?");DB::bind(st,1,t.challenge_id);DB::bind(st,2,t.dataset_hash);DB::bind(st,3,t.model_hash);bool ok=sqlite3_step(st)==SQLITE_ROW;sqlite3_finalize(st);return ok;}

    void validate_sig(const Tx&t,const std::string&m,bool allow_multisig=false) const {
        if(t.type=="MULTISIG_TRANSFER"||t.type=="GOV_PARAM"){
            if(!allow_multisig)throw std::runtime_error("multisig not allowed for this transaction");
            if(t.sender.rfind("MERA2",0)!=0||!valid_address(t.sender))throw std::runtime_error("invalid multisig sender");
            auto ks=signer_keys(t),ss=signer_sigs(t);if(t.multisig_threshold==0||ks.size()!=ss.size()||ks.size()>MAX_SIGNERS||t.multisig_threshold>ks.size())throw std::runtime_error("invalid multisig authorization");
            std::vector<std::string> sorted=ks;std::sort(sorted.begin(),sorted.end());if(sorted!=ks)throw std::runtime_error("multisig keys must be sorted");
            std::set<std::string>uniq(ks.begin(),ks.end());if(uniq.size()!=ks.size())throw std::runtime_error("duplicate multisig signer");
            if(multisig_address(t.multisig_threshold,ks)!=t.sender)throw std::runtime_error("multisig address mismatch");
            size_t good=0;for(size_t i=0;i<ks.size();++i)if(verify_ed25519(ks[i],m,ss[i]))good++;if(good<t.multisig_threshold)throw std::runtime_error("multisig threshold not met");return;
        }
        if(!valid_address(t.sender)||t.sender.rfind("MERA1",0)!=0)throw std::runtime_error("invalid sender address");
        if(address_from_pubkey(t.public_key)!=t.sender)throw std::runtime_error("sender/public key mismatch");
        if(!verify_ed25519(t.public_key,m,t.signature))throw std::runtime_error("invalid Ed25519 signature");
    }

    uint64_t pending_count_for(const std::string&s) const {auto st=db.prepare("SELECT COUNT(*) FROM pending WHERE sender=?");DB::bind(st,1,s);uint64_t n=0;if(sqlite3_step(st)==SQLITE_ROW)n=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);return n;}
    uint64_t pending_max_nonce(const std::string&s) const {auto st=db.prepare("SELECT COALESCE(MAX(nonce),0) FROM pending WHERE sender=?");DB::bind(st,1,s);uint64_t n=0;if(sqlite3_step(st)==SQLITE_ROW)n=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);return n;}
    uint64_t pending_reserved(const std::string&s) const {auto st=db.prepare("SELECT COALESCE(SUM(amount+fee),0) FROM pending WHERE sender=? AND type IN ('TRANSFER','MULTISIG_TRANSFER','CHALLENGE_REGISTER')");DB::bind(st,1,s);uint64_t n=0;if(sqlite3_step(st)==SQLITE_ROW)n=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);return n;}

    void validate_common_nonce(const Tx&t,const Replay&rv) const {
        uint64_t expected=rv.nonce(t.sender)+1;if(t.nonce!=expected)throw std::runtime_error("invalid account nonce");
    }

    void validate_one(const Tx&t,Replay&rv,uint64_t block_height,bool include_side_effects) const {
        if(tx_size(t)>MAX_TX_BYTES||t.payload_note.size()>MAX_NOTE_BYTES)throw std::runtime_error("transaction too large");
        rv.activate(block_height);
        if(t.type=="TRANSFER"){
            if(!valid_address(t.recipient)||t.recipient.rfind("MERA1",0)!=0||t.amount==0)throw std::runtime_error("invalid transfer");
            if(t.fee<rv.params.min_fee)throw std::runtime_error("fee below minimum");
            if(!rv.acct(t.sender).auth_pubkey.empty() && rv.acct(t.sender).auth_pubkey!=t.public_key) throw std::runtime_error("sender key is not current authorization key"); if(rv.acct(t.sender).auth_pubkey.empty() && address_from_pubkey(t.public_key)!=t.sender) throw std::runtime_error("sender/public key mismatch"); validate_sig(t,transfer_message(t));validate_common_nonce(t,rv);uint128_t need=uint128_t(t.amount)+t.fee;if(rv.balance(t.sender)<need)throw std::runtime_error("insufficient balance");
            if(include_side_effects){auto&s=rv.acct(t.sender);s.balance-=t.amount+t.fee;s.nonce=t.nonce;rv.acct(t.recipient).balance+=t.amount;rv.supply-=t.fee;if(rv.acct(t.sender).auth_pubkey.empty())rv.acct(t.sender).auth_pubkey=t.public_key;}
            return;
        }
        if(t.type=="MULTISIG_TRANSFER"){
            if(!valid_address(t.recipient)||t.recipient.rfind("MERA1",0)!=0||t.amount==0)throw std::runtime_error("invalid multisig transfer");
            if(t.fee<rv.params.min_fee)throw std::runtime_error("fee below minimum");
            validate_sig(t,multisig_transfer_message(t),true);validate_common_nonce(t,rv);uint128_t need=uint128_t(t.amount)+t.fee;if(rv.balance(t.sender)<need)throw std::runtime_error("insufficient multisig balance");
            if(include_side_effects){rv.acct(t.sender).balance-=t.amount+t.fee;rv.acct(t.sender).nonce=t.nonce;rv.acct(t.recipient).balance+=t.amount;rv.supply-=t.fee;}
            return;
        }
        if(t.type=="KEY_ROTATE"){
            auto na=unhex(t.new_public_key);if(na.size()!=32)throw std::runtime_error("invalid new key");if(rv.acct(t.sender).auth_pubkey.empty()){ if(address_from_pubkey(t.public_key)!=t.sender) throw std::runtime_error("rotation source key mismatch"); } else if(rv.acct(t.sender).auth_pubkey!=t.public_key) throw std::runtime_error("rotation source key is not current"); validate_sig(t,key_rotate_message(t));validate_common_nonce(t,rv);auto &a=rv.acct(t.sender);if(!a.auth_pubkey.empty()&&a.auth_pubkey!=t.public_key)throw std::runtime_error("key is not current authorization key");if(include_side_effects){a.nonce=t.nonce;a.auth_pubkey=t.new_public_key;}return;
        }
        if(t.type=="CHALLENGE_REGISTER"){
            if(t.fee<rv.params.challenge_bond)throw std::runtime_error("challenge bond/fee too small");
            if(t.challenge_id.empty()||t.manifest_hash.size()!=64||t.dataset_hash.size()!=64||t.challenge_verifier!=NATIVE_VERIFIER||t.challenge_metric!="NMSE"||t.challenge_split_rule!="first_fraction")throw std::runtime_error("invalid challenge registration");
            if(t.n_train<MIN_CHALLENGE_SAMPLES||t.n_train>MAX_CHALLENGE_SAMPLES||t.n_features==0||t.n_features>4096||t.challenge_train_fraction_ppm<100000||t.challenge_train_fraction_ppm>999999||t.challenge_max_epochs==0||t.challenge_max_epochs>100000||t.baseline_scaled!=1000000000ULL||t.challenge_budget==0||t.challenge_budget>MAX_CHALLENGE_BUDGET)throw std::runtime_error("challenge parameters outside protocol bounds");
            if(!rv.acct(t.sender).auth_pubkey.empty() && rv.acct(t.sender).auth_pubkey!=t.public_key) throw std::runtime_error("sender key is not current authorization key"); if(rv.acct(t.sender).auth_pubkey.empty() && address_from_pubkey(t.public_key)!=t.sender) throw std::runtime_error("sender/public key mismatch"); validate_sig(t,challenge_message(t));validate_common_nonce(t,rv);if(rv.challenges.count(t.challenge_id))throw std::runtime_error("challenge id already registered");{uint64_t active=0;for(const auto &[id,cx]:rv.challenges)if(cx.proposer==t.sender&&block_height<=cx.expiry_height)++active;if(active>=MAX_ACTIVE_CHALLENGES_PER_PROPOSER)throw std::runtime_error("active challenge limit reached for proposer");}uint128_t need=t.fee;if(rv.balance(t.sender)<need)throw std::runtime_error("insufficient balance for challenge bond");
            if(include_side_effects){auto&a=rv.acct(t.sender);a.balance-=t.fee;a.nonce=t.nonce;rv.supply-=t.fee;ChallengeState c;c.id=t.challenge_id;c.manifest_hash=t.manifest_hash;c.dataset_hash=t.dataset_hash;c.verifier=t.challenge_verifier;c.metric=t.challenge_metric;c.split_rule=t.challenge_split_rule;c.n_samples=t.n_train;c.n_features=t.n_features;c.train_fraction_ppm=t.challenge_train_fraction_ppm;c.max_epochs=t.challenge_max_epochs;c.baseline_scaled=t.baseline_scaled;c.created_height=block_height;c.activation_height=block_height+CHALLENGE_MATURITY;c.expiry_height=block_height+CHALLENGE_LIFETIME;c.budget_remaining=t.challenge_budget;c.proposer=t.sender;rv.challenges[c.id]=c;}
            return;
        }
        if(t.type=="ML_WORK"){
            if(t.fee<rv.params.min_work_fee)throw std::runtime_error("ML work fee below minimum");
            if(t.challenge_id.empty()||t.manifest_hash.size()!=64||t.dataset_hash.size()!=64||t.model_hash.size()!=64||t.arch_hash.size()!=64||t.challenge_id.empty())throw std::runtime_error("incomplete ML certificate");
            if(!t.ops||!t.n_train||!t.n_features||!t.epochs||t.ops>MAX_OPS_PER_WORK||!t.baseline_scaled||!t.nmse_scaled)throw std::runtime_error("invalid ML work fields");
            auto ci=rv.challenges.find(t.challenge_id);if(ci==rv.challenges.end())throw std::runtime_error("challenge is not registered");auto &c=ci->second;
            if(block_height<c.activation_height||block_height>c.expiry_height)throw std::runtime_error("challenge is not active");
            if(c.manifest_hash!=t.manifest_hash||c.dataset_hash!=t.dataset_hash||c.verifier!=NATIVE_VERIFIER||c.metric!="NMSE"||c.split_rule!="first_fraction")throw std::runtime_error("challenge certificate mismatch");
            if(t.n_train!=static_cast<uint64_t>((c.n_samples*c.train_fraction_ppm)/1000000ULL)||t.n_features!=c.n_features||t.epochs>c.max_epochs||t.baseline_scaled!=c.baseline_scaled)throw std::runtime_error("ML dimensions/config do not match challenge");
            if(t.ops!=checked_work_ops(t.epochs,t.n_train,t.n_features))throw std::runtime_error("symbolic operation count mismatch");
            if(!rv.acct(t.sender).auth_pubkey.empty() && rv.acct(t.sender).auth_pubkey!=t.public_key) throw std::runtime_error("sender key is not current authorization key"); if(rv.acct(t.sender).auth_pubkey.empty() && address_from_pubkey(t.public_key)!=t.sender) throw std::runtime_error("sender/public key mismatch"); validate_sig(t,ml_message(t));validate_common_nonce(t,rv);if(rv.balance(t.sender)<t.fee)throw std::runtime_error("insufficient balance for ML work fee");if(rv.supply<t.fee && t.work_reward<t.fee)throw std::runtime_error("fee exceeds current supply");
            std::string claim=c.id+"|"+t.dataset_hash+"|"+t.model_hash;if(rv.work_claims.count(claim))throw std::runtime_error("duplicate ML work claim");
            uint64_t q=quality_ppm(t);if(q<=c.best_quality_ppm)throw std::runtime_error("ML result does not improve challenge best");uint64_t delta=q-c.best_quality_ppm;uint64_t expected=work_reward_for_quality(t.ops,delta);if(t.work_reward!=expected||!t.work_reward)throw std::runtime_error("ML reward mismatch");if(t.work_reward>c.budget_remaining)throw std::runtime_error("challenge reward budget exceeded");
            if(include_side_effects){auto&a=rv.acct(t.sender);a.balance+=t.work_reward-t.fee;a.nonce=t.nonce;if(t.work_reward>=t.fee) rv.supply+=t.work_reward-t.fee; else rv.supply-=t.fee-t.work_reward; c.best_quality_ppm=q;c.best_model_hash=t.model_hash;c.budget_remaining-=t.work_reward;rv.work_claims.insert(claim);}
            return;
        }
        if(t.type=="GOV_PARAM"){
            if(meta("governance_address").empty() || t.sender!=meta("governance_address")) throw std::runtime_error("governance is not configured");
            if(meta("governance_threshold", "0") != std::to_string(t.multisig_threshold) || meta("governance_keys") != t.multisig_keys) throw std::runtime_error("governance signer set mismatch");
            validate_sig(t,gov_message(t),true);validate_common_nonce(t,rv);std::set<std::string>allowed={"min_fee","min_work_fee","challenge_bond"};if(!allowed.count(t.gov_key))throw std::runtime_error("governance parameter not allowed");uint64_t v=u64(t.gov_value);if(t.gov_effective_height<block_height+GOVERNANCE_TIMELOCK)throw std::runtime_error("governance change timelock not met");if(v==0)throw std::runtime_error("governance parameter cannot be zero");if(include_side_effects){rv.acct(t.sender).nonce=t.nonce;rv.scheduled_params[t.gov_key]={t.gov_effective_height,v};}return;
        }
        if(t.type=="FAUCET"){
            if(meta("faucet_enabled")!="1")throw std::runtime_error("faucet disabled by chain genesis");if(!valid_address(t.recipient)||t.recipient.rfind("MERA1",0)!=0||t.amount==0)throw std::runtime_error("invalid faucet tx");if(uint128_t(rv.supply)+t.amount>MAX_SUPPLY)throw std::runtime_error("maximum supply exceeded");if(include_side_effects){rv.acct(t.recipient).balance+=t.amount;rv.supply+=t.amount;}return;
        }
        throw std::runtime_error("unsupported tx type");
    }

    Replay current_replay() const {Replay r;r.supply=0;r.params=genesis_params();for(uint64_t h=1;h<=height();++h){Block b=load_block(h);r.activate(h);for(auto &t:b.transactions)validate_one(t,r,h,true);}return r;}

    void insert_tx(Block&b,size_t ord,const Tx&t){auto st=db.prepare("INSERT INTO txs(txid,height,ord,type,sender,recipient,amount,fee,nonce,challenge_id,manifest_hash,dataset_hash,model_hash,arch_hash,ops,n_train,n_features,epochs,nmse_scaled,baseline_scaled,work_reward,wall_ms,lswu_micro,public_key,signature,payload_note,challenge_train_fraction_ppm,challenge_max_epochs,challenge_budget,challenge_verifier,challenge_metric,challenge_split_rule,new_public_key,multisig_threshold,multisig_keys,multisig_sigs,gov_key,gov_value,gov_effective_height) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");int i=1;auto s=[&](const std::string&x){DB::bind(st,i++,x);};auto n=[&](uint64_t x){DB::bind(st,i++,x);};s(t.txid);n(b.height);n(static_cast<uint64_t>(ord));s(t.type);s(t.sender);s(t.recipient);n(t.amount);n(t.fee);n(t.nonce);s(t.challenge_id);s(t.manifest_hash);s(t.dataset_hash);s(t.model_hash);s(t.arch_hash);n(t.ops);n(t.n_train);n(t.n_features);n(t.epochs);n(t.nmse_scaled);n(t.baseline_scaled);n(t.work_reward);n(t.wall_ms);n(t.lswu_micro);s(t.public_key);s(t.signature);s(t.payload_note);n(t.challenge_train_fraction_ppm);n(t.challenge_max_epochs);n(t.challenge_budget);s(t.challenge_verifier);s(t.challenge_metric);s(t.challenge_split_rule);s(t.new_public_key);n(t.multisig_threshold);s(t.multisig_keys);s(t.multisig_sigs);s(t.gov_key);s(t.gov_value);n(t.gov_effective_height);if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error("tx insert: "+e);}sqlite3_finalize(st);}
    void insert_pending(const Tx&t){auto st=db.prepare("INSERT INTO pending(txid,type,sender,recipient,amount,fee,nonce,challenge_id,manifest_hash,dataset_hash,model_hash,arch_hash,ops,n_train,n_features,epochs,nmse_scaled,baseline_scaled,work_reward,wall_ms,lswu_micro,public_key,signature,payload_note,challenge_train_fraction_ppm,challenge_max_epochs,challenge_budget,challenge_verifier,challenge_metric,challenge_split_rule,new_public_key,multisig_threshold,multisig_keys,multisig_sigs,gov_key,gov_value,gov_effective_height) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");int i=1;auto s=[&](const std::string&x){DB::bind(st,i++,x);};auto n=[&](uint64_t x){DB::bind(st,i++,x);};s(t.txid);s(t.type);s(t.sender);s(t.recipient);n(t.amount);n(t.fee);n(t.nonce);s(t.challenge_id);s(t.manifest_hash);s(t.dataset_hash);s(t.model_hash);s(t.arch_hash);n(t.ops);n(t.n_train);n(t.n_features);n(t.epochs);n(t.nmse_scaled);n(t.baseline_scaled);n(t.work_reward);n(t.wall_ms);n(t.lswu_micro);s(t.public_key);s(t.signature);s(t.payload_note);n(t.challenge_train_fraction_ppm);n(t.challenge_max_epochs);n(t.challenge_budget);s(t.challenge_verifier);s(t.challenge_metric);s(t.challenge_split_rule);s(t.new_public_key);n(t.multisig_threshold);s(t.multisig_keys);s(t.multisig_sigs);s(t.gov_key);s(t.gov_value);n(t.gov_effective_height);if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error("pending insert: "+e);}sqlite3_finalize(st);}
    Tx row_tx_pending(sqlite3_stmt*st) const {Tx t;int c=0;auto ct=[&](){auto p=sqlite3_column_text(st,c++);return p?std::string(reinterpret_cast<const char*>(p)):std::string();};auto cu=[&](){return static_cast<uint64_t>(sqlite3_column_int64(st,c++));};t.txid=ct();t.type=ct();t.sender=ct();t.recipient=ct();t.amount=cu();t.fee=cu();t.nonce=cu();t.challenge_id=ct();t.manifest_hash=ct();t.dataset_hash=ct();t.model_hash=ct();t.arch_hash=ct();t.ops=cu();t.n_train=cu();t.n_features=cu();t.epochs=cu();t.nmse_scaled=cu();t.baseline_scaled=cu();t.work_reward=cu();t.wall_ms=cu();t.lswu_micro=cu();t.public_key=ct();t.signature=ct();t.payload_note=ct();t.challenge_train_fraction_ppm=cu();t.challenge_max_epochs=cu();t.challenge_budget=cu();t.challenge_verifier=ct();t.challenge_metric=ct();t.challenge_split_rule=ct();t.new_public_key=ct();t.multisig_threshold=cu();t.multisig_keys=ct();t.multisig_sigs=ct();t.gov_key=ct();t.gov_value=ct();t.gov_effective_height=cu();return t;}
    std::vector<Tx> pending_all() const {std::vector<Tx>out;auto st=db.prepare("SELECT txid,type,sender,recipient,amount,fee,nonce,challenge_id,manifest_hash,dataset_hash,model_hash,arch_hash,ops,n_train,n_features,epochs,nmse_scaled,baseline_scaled,work_reward,wall_ms,lswu_micro,public_key,signature,payload_note,challenge_train_fraction_ppm,challenge_max_epochs,challenge_budget,challenge_verifier,challenge_metric,challenge_split_rule,new_public_key,multisig_threshold,multisig_keys,multisig_sigs,gov_key,gov_value,gov_effective_height FROM pending ORDER BY seq");while(sqlite3_step(st)==SQLITE_ROW)out.push_back(row_tx_pending(st));sqlite3_finalize(st);return out;}

    void submit(Tx t){t.txid=txid(t);if(tx_size(t)>MAX_TX_BYTES)throw std::runtime_error("transaction too large");if(t.payload_note.size()>MAX_NOTE_BYTES)throw std::runtime_error("note too large");if(t.type=="TRANSFER"||t.type=="ML_WORK"||t.type=="CHALLENGE_REGISTER"||t.type=="KEY_ROTATE"||t.type=="GOV_PARAM"){if(pending_count_for(t.sender)>=MAX_PENDING_PER_SENDER)throw std::runtime_error("per-sender pending limit reached");uint64_t expected=nonce(t.sender)+pending_count_for(t.sender)+1;if(t.nonce!=expected)throw std::runtime_error("pending-aware nonce mismatch");uint64_t reserved=pending_reserved(t.sender);if(t.type=="TRANSFER"||t.type=="CHALLENGE_REGISTER")reserved+=t.amount+t.fee;else if(t.type=="ML_WORK")reserved+=t.fee;if(balance(t.sender)<reserved)throw std::runtime_error("insufficient balance after pending reservations");}
        auto st=db.prepare("SELECT 1 FROM txs WHERE txid=? UNION SELECT 1 FROM pending WHERE txid=? LIMIT 1");DB::bind(st,1,t.txid);DB::bind(st,2,t.txid);bool exists=sqlite3_step(st)==SQLITE_ROW;sqlite3_finalize(st);if(exists)throw std::runtime_error("duplicate transaction");
        Replay r=current_replay();uint64_t h=height();for(const auto &pt:pending_all()){try{validate_one(pt,r,h+1,true);}catch(...){}}validate_one(t,r,h+1,false);if(pending_all().size()>=MAX_MEMPOOL_TX)throw std::runtime_error("mempool full");insert_pending(t);std::cout<<"TXID="<<t.txid<<"\nSTATUS=accepted\n";
    }

    void faucet(const std::string&recipient,uint64_t amount){if(meta("faucet_enabled")!="1")throw std::runtime_error("faucet disabled by chain genesis");Tx t;t.type="FAUCET";t.recipient=recipient;t.amount=amount;t.txid=txid(t);Replay r=current_replay();validate_one(t,r,height()+1,false);insert_pending(t);std::cout<<"TXID="<<t.txid<<"\nSTATUS=accepted\n";}

    int expected_difficulty_for(uint64_t next_height,const std::vector<Block>&chain) const {
        if(next_height==0)return 0;if(next_height<=DIFFICULTY_WINDOW)return BASE_DIFFICULTY;int d=chain.back().difficulty;if(next_height%DIFFICULTY_WINDOW!=0)return d;uint64_t parent_h=next_height-1;uint64_t start_h=next_height-DIFFICULTY_WINDOW-1;if(start_h>=chain.size())return d;uint64_t elapsed=chain[parent_h].timestamp_ms-chain[start_h].timestamp_ms;uint64_t target=params().target_block_ms*DIFFICULTY_WINDOW;if(elapsed<target/2)return std::min(d+1,MAX_DIFFICULTY);if(elapsed>target*2)return std::max(d-1,MIN_DIFFICULTY);return d;
    }
    std::vector<Block> canonical_chain() const {std::vector<Block>out;for(uint64_t h=0;h<=height();++h)out.push_back(load_block(h));return out;}
    uint256_t cumulative_work(const std::vector<Block>&c) const {return c.empty()?0:c.back().chain_work;}

    std::vector<Tx> select_for_block(const std::vector<Tx>&p,uint64_t next_height,const std::string&producer) const {
        std::vector<size_t> order(p.size());for(size_t i=0;i<p.size();++i)order[i]=i;std::sort(order.begin(),order.end(),[&](size_t a,size_t b){if(p[a].fee!=p[b].fee)return p[a].fee>p[b].fee;return p[a].txid<p[b].txid;});
        Replay r=current_replay();std::vector<Tx> chosen;std::set<size_t> used;uint64_t bytes=0,ops=0,rewards=0;bool progress=true;
        while(progress&&chosen.size()<MAX_BLOCK_TX){progress=false;for(size_t idx:order){if(used.count(idx))continue;Tx t=p[idx];try{Replay test=r;validate_one(t,test,next_height,true);uint64_t nb=bytes+tx_size(t)+8;if(nb>params().max_block_bytes)continue;chosen.push_back(t);used.insert(idx);r=std::move(test);bytes=nb;ops+=t.ops;rewards+=t.work_reward;progress=true;if(chosen.size()>=MAX_BLOCK_TX)break;}catch(...){continue;}}}
        (void)producer;(void)ops;(void)rewards;return chosen;
    }

    Block block_template(const std::string&producer,const std::string&pubkey,uint64_t timestamp_hint=0) const {
        if(!valid_address(producer)||producer.rfind("MERA1",0)!=0)throw std::runtime_error("invalid producer address");if(address_from_pubkey(pubkey)!=producer)throw std::runtime_error("producer/public key mismatch");auto p=pending_all();std::vector<Block>cc=canonical_chain();uint64_t h=height()+1;Block b;b.height=h;b.timestamp_ms=timestamp_hint?timestamp_hint:std::max(now_ms(),cc.back().timestamp_ms+1);b.previous_hash=cc.back().block_hash;b.difficulty=expected_difficulty_for(h,cc);b.producer=producer;b.producer_pubkey=pubkey;b.transactions=select_for_block(p,h,producer);b.merkle_root=merkle_root(b.transactions);b.total_ops=0;b.total_rewards=0;for(auto&t:b.transactions){b.total_ops+=t.ops;b.total_rewards+=t.work_reward;}b.producer_signature="";b.nonce=0;return b;
    }

    void mine(const std::string&producer,const std::string&pubkey,const std::string&sig,uint64_t timestamp_hint=0){Block b=block_template(producer,pubkey,timestamp_hint);b.producer_signature=sig;if(sig.empty())throw std::runtime_error("producer signature required");if(!verify_ed25519(pubkey,block_signing_message(b),sig))throw std::runtime_error("invalid block producer signature");b.block_hash=mine_hash(b);b.chain_work=pow_work(b.difficulty)+(height()?load_block(height()).chain_work:uint256_t(0));uint64_t hs=now_ms();if(b.timestamp_ms>hs+MAX_FUTURE_MS||b.timestamp_ms<=median_time_past(canonical_chain()))throw std::runtime_error("invalid block timestamp");commit_block(b);std::cout<<"HEIGHT="<<b.height<<"\nBLOCK_HASH="<<b.block_hash<<"\nCHAIN_WORK="<<b.chain_work<<"\nTOTAL_OPS="<<b.total_ops<<"\nTOTAL_REWARD_ATOMIC="<<b.total_rewards<<"\nTX_COUNT="<<b.transactions.size()<<"\n";}

    void commit_block(Block b){
        auto cc=canonical_chain();if(b.height!=cc.back().height+1||b.previous_hash!=cc.back().block_hash)throw std::runtime_error("block does not extend current tip");Replay r=current_replay();for(auto&t:b.transactions)validate_one(t,r,b.height,true);if(b.merkle_root!=merkle_root(b.transactions))throw std::runtime_error("Merkle root mismatch");if(block_size(b)>params().max_block_bytes)throw std::runtime_error("block exceeds byte limit");if(b.total_ops!=std::accumulate(b.transactions.begin(),b.transactions.end(),uint64_t(0),[](uint64_t x,const Tx&t){return x+t.ops;}))throw std::runtime_error("block ops counter mismatch");if(b.total_rewards!=std::accumulate(b.transactions.begin(),b.transactions.end(),uint64_t(0),[](uint64_t x,const Tx&t){return x+t.work_reward;}))throw std::runtime_error("block reward counter mismatch");if(b.block_hash!=sha256(block_header(b))||b.block_hash.rfind(std::string(b.difficulty,'0'),0)!=0)throw std::runtime_error("block PoW/hash invalid");
        db.exec("BEGIN IMMEDIATE;");try{insert_block_header(b);for(size_t i=0;i<b.transactions.size();++i)insert_tx(b,i,b.transactions[i]);apply_replay_to_db(r);db.exec("DELETE FROM pending WHERE txid IN (SELECT txid FROM txs WHERE height="+std::to_string(b.height)+")");db.exec("COMMIT;");}catch(...){db.exec("ROLLBACK;");throw;}
    }

    void apply_replay_to_db(const Replay&r){db.exec("DELETE FROM accounts;");for(auto &[a,x]:r.accounts)set_account(a,x);db.exec("DELETE FROM challenges;");for(auto &[id,c]:r.challenges){auto st=db.prepare("INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");int i=1;auto s=[&](const std::string&v){DB::bind(st,i++,v);};auto n=[&](uint64_t v){DB::bind(st,i++,v);};s(c.id);s(c.manifest_hash);s(c.dataset_hash);s(c.verifier);s(c.metric);s(c.split_rule);n(c.n_samples);n(c.n_features);n(c.train_fraction_ppm);n(c.max_epochs);n(c.baseline_scaled);n(c.created_height);n(c.activation_height);n(c.expiry_height);n(c.budget_remaining);n(c.best_quality_ppm);s(c.best_model_hash);s(c.proposer);if(sqlite3_step(st)!=SQLITE_DONE){std::string e=sqlite3_errmsg(db.db);sqlite3_finalize(st);throw std::runtime_error(e);}sqlite3_finalize(st);}db.exec("DELETE FROM work_claims;");db.exec("INSERT INTO work_claims(challenge_id,dataset_hash,model_hash,txid,height) SELECT challenge_id,dataset_hash,model_hash,txid,height FROM txs WHERE type='ML_WORK';");
        set_supply(r.supply);set_param_meta(r.params);
        db.exec("DELETE FROM gov_updates;");for(auto &[k,p]:r.scheduled_params){auto st=db.prepare("INSERT INTO gov_updates(param_key,param_value,effective_height,txid) VALUES(?,?,?,?) ON CONFLICT(param_key) DO UPDATE SET param_value=excluded.param_value,effective_height=excluded.effective_height,txid=excluded.txid");DB::bind(st,1,k);DB::bind(st,2,p.second);DB::bind(st,3,p.first);DB::bind(st,4,"");sqlite3_step(st);sqlite3_finalize(st);}
    }

    void accept_chain(const std::vector<Block>&candidate){if(candidate.empty())throw std::runtime_error("empty candidate chain");if(candidate[0].height!=0)throw std::runtime_error("candidate missing genesis");if(candidate[0].block_hash!=load_block(0).block_hash)throw std::runtime_error("genesis mismatch");Replay r;r.supply=0;r.params=genesis_params();uint256_t work=0;std::string prev= candidate[0].block_hash;
        for(size_t i=0;i<candidate.size();++i){const Block&b=candidate[i];if(i==0){if(b.difficulty!=0||b.previous_hash!=std::string(64,'0'))throw std::runtime_error("invalid genesis");work=0;continue;}if(b.height!=candidate[i-1].height+1||b.previous_hash!=prev)throw std::runtime_error("broken candidate chain");if(b.timestamp_ms<=median_time_past(std::vector<Block>(candidate.begin(),candidate.begin()+i))||b.timestamp_ms>now_ms()+MAX_FUTURE_MS)throw std::runtime_error("candidate timestamp invalid");int ed=expected_difficulty_for(b.height,std::vector<Block>(candidate.begin(),candidate.begin()+i));if(b.difficulty!=ed)throw std::runtime_error("candidate difficulty mismatch");if(!producer_authorized(b,r)||!verify_ed25519(b.producer_pubkey,block_signing_message(b),b.producer_signature))throw std::runtime_error("candidate producer signature invalid");if(b.block_hash!=sha256(block_header(b))||b.block_hash.rfind(std::string(b.difficulty,'0'),0)!=0)throw std::runtime_error("candidate PoW invalid");if(b.merkle_root!=merkle_root(b.transactions))throw std::runtime_error("candidate Merkle mismatch");if(b.transactions.size()>MAX_BLOCK_TX||block_size(b)>params().max_block_bytes)throw std::runtime_error("candidate block size exceeded");uint64_t ops=0,rewards=0;for(auto&t:b.transactions){validate_one(t,r,b.height,true);ops+=t.ops;rewards+=t.work_reward;}if(ops!=b.total_ops||rewards!=b.total_rewards)throw std::runtime_error("candidate block counters mismatch");work+=pow_work(b.difficulty);if(work!=b.chain_work)throw std::runtime_error("candidate chain work mismatch");prev=b.block_hash;}
        uint256_t local=load_block(height()).chain_work;if(work<local||(work==local&&candidate.back().block_hash>=tip_hash()))throw std::runtime_error("candidate does not beat local fork-choice rule");
        std::vector<Tx> old_pending=pending_all();db.exec("BEGIN IMMEDIATE;");try{db.exec("DELETE FROM txs;");db.exec("DELETE FROM blocks WHERE height>0;");db.exec("DELETE FROM accounts;");db.exec("DELETE FROM challenges;");db.exec("DELETE FROM work_claims;");for(size_t i=1;i<candidate.size();++i){const Block&b=candidate[i];insert_block_header(b);for(size_t j=0;j<b.transactions.size();++j)insert_tx(const_cast<Block&>(b),j,b.transactions[j]);}apply_replay_to_db(r);db.exec("DELETE FROM pending;");db.exec("COMMIT;");}catch(...){db.exec("ROLLBACK;");throw;}
        for(auto &t:old_pending){try{submit(t);}catch(...){}}
        std::cout<<"SYNCED_HEIGHT="<<height()<<"\nSYNCED_TIP="<<tip_hash()<<"\nCHAIN_WORK="<<candidate.back().chain_work<<"\n";
    }

    bool producer_authorized(const Block&b,const Replay&rv) const {
        if(!valid_address(b.producer)||b.producer.rfind("MERA1",0)!=0) return false;
        auto it=rv.accounts.find(b.producer);
        if(it!=rv.accounts.end() && !it->second.auth_pubkey.empty()) return it->second.auth_pubkey==b.producer_pubkey;
        return address_from_pubkey(b.producer_pubkey)==b.producer;
    }

    void validate_chain(bool verbose=true) const {auto chain=canonical_chain();if(chain.empty())throw std::runtime_error("empty chain");Replay r;r.supply=0;r.params=genesis_params();uint256_t work=0;for(size_t i=0;i<chain.size();++i){const Block&b=chain[i];if(i==0){if(b.previous_hash!=std::string(64,'0'))throw std::runtime_error("invalid genesis");continue;}if(b.height!=chain[i-1].height+1||b.previous_hash!=chain[i-1].block_hash)throw std::runtime_error("broken chain");if(b.timestamp_ms<=median_time_past(std::vector<Block>(chain.begin(),chain.begin()+i))||b.timestamp_ms>now_ms()+MAX_FUTURE_MS)throw std::runtime_error("timestamp invalid");int ed=expected_difficulty_for(b.height,std::vector<Block>(chain.begin(),chain.begin()+i));if(b.difficulty!=ed)throw std::runtime_error("difficulty invalid at height "+std::to_string(b.height));if(!valid_address(b.producer)||address_from_pubkey(b.producer_pubkey)!=b.producer||!verify_ed25519(b.producer_pubkey,block_signing_message(b),b.producer_signature))throw std::runtime_error("producer auth invalid");if(b.block_hash!=sha256(block_header(b))||b.block_hash.rfind(std::string(b.difficulty,'0'),0)!=0)throw std::runtime_error("PoW invalid");if(b.merkle_root!=merkle_root(b.transactions))throw std::runtime_error("Merkle invalid");uint64_t ops=0,rewards=0;for(auto&t:b.transactions){validate_one(t,r,b.height,true);ops+=t.ops;rewards+=t.work_reward;}if(ops!=b.total_ops||rewards!=b.total_rewards)throw std::runtime_error("block counter mismatch");work+=pow_work(b.difficulty);if(work!=b.chain_work)throw std::runtime_error("chain work mismatch");}
        for(auto &[a,x]:r.accounts){auto dbx=account(a);if(dbx.balance!=x.balance||dbx.nonce!=x.nonce||dbx.auth_pubkey!=x.auth_pubkey)throw std::runtime_error("account state mismatch for "+a);}
        {auto q=db.prepare("SELECT address FROM accounts");std::set<std::string> dbaddrs;while(sqlite3_step(q)==SQLITE_ROW){auto p=sqlite3_column_text(q,0);if(p)dbaddrs.insert(reinterpret_cast<const char*>(p));}sqlite3_finalize(q);std::set<std::string> raddrs;for(auto &[a,_]:r.accounts)raddrs.insert(a);if(dbaddrs!=raddrs)throw std::runtime_error("database contains account rows outside replay state");}
        if(r.supply!=total_supply())throw std::runtime_error("supply mismatch");if(total_supply()>MAX_SUPPLY)throw std::runtime_error("supply cap exceeded");if(verbose)std::cout<<"STATUS=VALID\nBLOCKS="<<chain.size()<<"\nTRANSACTIONS="<<count_txs()<<"\nTOTAL_SUPPLY_ATOMIC="<<total_supply()<<"\nTOTAL_SUPPLY_MERA="<<std::fixed<<std::setprecision(8)<<(double)total_supply()/ATOMIC_PER_MERA<<"\n";
    }
    uint64_t count_txs() const {auto st=db.prepare("SELECT COUNT(*) FROM txs");uint64_t n=0;if(sqlite3_step(st)==SQLITE_ROW)n=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);return n;}

    void print_status() const {auto h=height();auto st=db.prepare("SELECT COUNT(*) FROM pending");uint64_t p=0;if(sqlite3_step(st)==SQLITE_ROW)p=static_cast<uint64_t>(sqlite3_column_int64(st,0));sqlite3_finalize(st);auto st2=db.prepare("SELECT COALESCE(SUM(ops),0),COALESCE(SUM(work_reward),0),COALESCE(SUM(fee),0) FROM txs");uint64_t ops=0,r=0,f=0;if(sqlite3_step(st2)==SQLITE_ROW){ops=static_cast<uint64_t>(sqlite3_column_int64(st2,0));r=static_cast<uint64_t>(sqlite3_column_int64(st2,1));f=static_cast<uint64_t>(sqlite3_column_int64(st2,2));}sqlite3_finalize(st2);std::cout<<"NETWORK="<<network<<"\nPROTOCOL_VERSION="<<PROTOCOL_VERSION<<"\nHEIGHT="<<h<<"\nTIP="<<tip_hash()<<"\nCHAIN_WORK="<<load_block(h).chain_work<<"\nPENDING="<<p<<"\nTRANSACTIONS="<<count_txs()<<"\nTOTAL_OPS="<<ops<<"\nTOTAL_ML_REWARD_MERA="<<std::fixed<<std::setprecision(8)<<(double)r/ATOMIC_PER_MERA<<"\nFEES_BURNED_MERA="<<(double)f/ATOMIC_PER_MERA<<"\nTOTAL_SUPPLY_MERA="<<(double)total_supply()/ATOMIC_PER_MERA<<"\nMAX_SUPPLY_MERA=100000000.00000000\nMIN_FEE_ATOMIC="<<params().min_fee<<"\nTARGET_BLOCK_MS="<<params().target_block_ms<<"\n";}

    void show_tx(const std::string&id) const {auto st=db.prepare("SELECT type,sender,recipient,amount,fee,nonce,challenge_id,manifest_hash,dataset_hash,model_hash,arch_hash,ops,n_train,n_features,epochs,nmse_scaled,baseline_scaled,work_reward,wall_ms,lswu_micro,public_key,signature,payload_note,challenge_verifier,multisig_threshold,multisig_keys,multisig_sigs,gov_key,gov_value,gov_effective_height FROM txs WHERE txid=?");DB::bind(st,1,id);if(sqlite3_step(st)!=SQLITE_ROW){sqlite3_finalize(st);throw std::runtime_error("transaction not found");}int c=0;auto ct=[&](const std::string&k){auto p=sqlite3_column_text(st,c++);std::cout<<k<<"="<<(p?reinterpret_cast<const char*>(p):"")<<"\n";};auto cu=[&](const std::string&k){std::cout<<k<<"="<<static_cast<uint64_t>(sqlite3_column_int64(st,c++))<<"\n";};ct("TYPE");ct("SENDER");ct("RECIPIENT");cu("AMOUNT_ATOMIC");cu("FEE_ATOMIC");cu("NONCE");ct("CHALLENGE_ID");ct("MANIFEST_SHA256");ct("DATASET_SHA256");ct("MODEL_SHA256");ct("ARCH_SHA256");cu("OPS");cu("N_TRAIN");cu("N_FEATURES");cu("EPOCHS");cu("NMSE_SCALED");cu("BASELINE_SCALED");cu("WORK_REWARD_ATOMIC");cu("WALL_MS");cu("LSWU_MICRO");ct("PUBLIC_KEY");ct("SIGNATURE");ct("NOTE");ct("CHALLENGE_VERIFIER");cu("MULTISIG_THRESHOLD");ct("MULTISIG_KEYS");ct("MULTISIG_SIGS");ct("GOV_KEY");ct("GOV_VALUE");cu("GOV_EFFECTIVE_HEIGHT");sqlite3_finalize(st);std::cout<<"TXID="<<id<<"\n";}

    void backup(const std::string&out) const {DB dest(out);sqlite3_backup*bk=sqlite3_backup_init(dest.db,"main",db.db,"main");if(!bk)throw std::runtime_error("sqlite backup init failed");int rc=sqlite3_backup_step(bk,-1);sqlite3_backup_finish(bk);if(rc!=SQLITE_DONE)throw std::runtime_error("sqlite backup failed");std::cout<<"BACKUP="<<std::filesystem::absolute(out).string()<<"\n";}
};

class P2P {
    State& state; std::string host; uint16_t port; std::vector<std::string> peers; std::atomic<bool> stop{false}; std::thread server_thread; std::mutex peers_mu;
public:
    P2P(State&s,const std::string&h,uint16_t p,const std::vector<std::string>&ps):state(s),host(h),port(p),peers(ps){}
    static std::pair<std::string,uint16_t> parse_endpoint(const std::string&e){auto p=e.rfind(':');if(p==std::string::npos)throw std::runtime_error("peer must be host:port");return {e.substr(0,p),static_cast<uint16_t>(u64(e.substr(p+1)))};}
    std::string request(const std::string&endpoint,const std::string&message) const {auto [h,p]=parse_endpoint(endpoint);boost::asio::io_context io;tcp::socket s(io);tcp::resolver resolver(io); auto eps=resolver.resolve(h,std::to_string(p)); boost::asio::connect(s,eps);boost::asio::write(s,boost::asio::buffer(message+"\n"));boost::asio::streambuf buf;boost::asio::read_until(s,buf,'\n');std::istream is(&buf);std::string line;std::getline(is,line);return line;}
    void broadcast_line(const std::string&line){std::lock_guard<std::mutex>g(peers_mu);for(auto &p:peers){try{(void)request(p,line);}catch(...){}}}
    void handle(tcp::socket socket){try{socket.non_blocking(false);boost::asio::streambuf buf;boost::asio::read_until(socket,buf,'\n');std::istream is(&buf);std::string line;std::getline(is,line);if(line.size()>16ULL*1024ULL*1024ULL){boost::asio::write(socket,boost::asio::buffer("ERROR|message-too-large\n"));return;}if(line=="PING"){boost::asio::write(socket,boost::asio::buffer("PONG\n"));return;}if(line=="STATUS"){std::ostringstream o;o<<"STATUS|"<<state.height()<<"|"<<state.tip_hash()<<"|"<<state.load_block(state.height()).chain_work<<"\n";boost::asio::write(socket,boost::asio::buffer(o.str()));return;}if(line=="GETCHAIN"){auto c=state.canonical_chain();for(auto &b:c){boost::asio::write(socket,boost::asio::buffer("BLOCK|"+hex_encode_text(encode_block(b))+"\n"));}boost::asio::write(socket,boost::asio::buffer("END\n"));return;}if(line.rfind("TX|",0)==0){Tx t=tx_from_wire(hex_decode_text(line.substr(3)));state.submit(t);boost::asio::write(socket,boost::asio::buffer("OK\n"));return;}if(line.rfind("BLOCK|",0)==0){Block b=decode_block(hex_decode_text(line.substr(6)));std::vector<Block>c=state.canonical_chain();if(b.previous_hash==c.back().block_hash){state.commit_block(b);boost::asio::write(socket,boost::asio::buffer("OK\n"));}else{boost::asio::write(socket,boost::asio::buffer("SYNC_REQUIRED\n"));}return;}boost::asio::write(socket,boost::asio::buffer("ERROR|unknown-command\n"));}catch(const std::exception&e){try{boost::asio::write(socket,boost::asio::buffer(std::string("ERROR|"+std::string(e.what())+"\n")));}catch(...){}}}
    void server(){boost::asio::io_context io;tcp::resolver resolver(io); auto eps=resolver.resolve(host,std::to_string(port)); tcp::acceptor a(io,*eps.begin());while(!stop){tcp::socket s(io);boost::system::error_code ec;a.accept(s,ec);if(ec){if(stop)break;continue;}std::thread(&P2P::handle,this,std::move(s)).detach();}}
    void start(){server_thread=std::thread([this]{server();});}
    void stop_now(){stop=true;try{boost::asio::io_context io;tcp::socket s(io);tcp::resolver resolver(io); auto eps=resolver.resolve(host,std::to_string(port)); boost::asio::connect(s,eps);}catch(...){}if(server_thread.joinable())server_thread.join();}
    void sync_once(){std::lock_guard<std::mutex>g(peers_mu);auto local_work=state.load_block(state.height()).chain_work;for(auto &p:peers){try{std::string hs=request(p,"STATUS");auto f=split(hs,'|');if(f.size()<4||f[0]!="STATUS")continue;uint256_t remote(f[3]);if(remote<local_work||(remote==local_work&&f[2]>=state.tip_hash()))continue;auto [h,pt]=parse_endpoint(p);boost::asio::io_context io;tcp::socket s(io);s.connect(tcp::endpoint(boost::asio::ip::make_address(h),pt));boost::asio::write(s,boost::asio::buffer("GETCHAIN\n"));boost::asio::streambuf buf;std::vector<Block>chain;for(;;){boost::asio::read_until(s,buf,'\n');std::istream is(&buf);std::string line;std::getline(is,line);if(line=="END")break;if(line.rfind("BLOCK|",0)==0)chain.push_back(decode_block(hex_decode_text(line.substr(6))));if(chain.size()>100000)throw std::runtime_error("peer chain exceeds sync limit");}state.accept_chain(chain);local_work=state.load_block(state.height()).chain_work;}catch(const std::exception&e){std::cerr<<"SYNC_ERROR="<<e.what()<<"\n";}}}
    void run(const uint64_t seconds=0){start();auto begin=std::chrono::steady_clock::now();while(!stop){std::this_thread::sleep_for(std::chrono::seconds(5));try{sync_once();}catch(...){}if(seconds && std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-begin).count()>=static_cast<long long>(seconds))break;}stop_now();}

    static std::string encode_block(const Block&b){std::vector<std::string>f={std::to_string(b.height),std::to_string(b.timestamp_ms),b.previous_hash,b.merkle_root,std::to_string(b.difficulty),std::to_string(b.nonce),b.producer,b.producer_pubkey,b.producer_signature,b.block_hash,std::to_string(b.total_ops),std::to_string(b.total_rewards),b.chain_work.convert_to<std::string>(),std::to_string(b.transactions.size())};for(auto&t:b.transactions)f.push_back(tx_wire(t));for(auto &x:f)x=hex_encode_text(x);return join(f,"|");}
    static Block decode_block(const std::string&w){auto f=split(w,'|');if(f.size()<14)throw std::runtime_error("malformed block wire");for(auto &x:f)x=hex_decode_text(x);size_t i=0;Block b;b.height=u64(f[i++]);b.timestamp_ms=u64(f[i++]);b.previous_hash=f[i++];b.merkle_root=f[i++];b.difficulty=std::stoi(f[i++]);b.nonce=u64(f[i++]);b.producer=f[i++];b.producer_pubkey=f[i++];b.producer_signature=f[i++];b.block_hash=f[i++];b.total_ops=u64(f[i++]);b.total_rewards=u64(f[i++]);b.chain_work=uint256_t(f[i++]);size_t n=u64(f[i++]);if(f.size()!=14+n)throw std::runtime_error("block tx count mismatch");for(size_t k=0;k<n;++k)b.transactions.push_back(tx_from_wire(f[i++]));return b;}
};


} // namespace

void usage(){
    std::cout << "Mera core v0.3\n"
              << "  init [--data-dir DIR] [--network devnet|testnet|mainnet] [--governance-keys pub1,pub2] [--governance-threshold N]\n"
              << "  balance --address ADDRESS\n"
              << "  nonce --address ADDRESS\n"
              << "  block-template --producer ADDRESS --public-key HEX\n"
              << "  submit-transfer ...\n"
              << "  submit-multisig-transfer ...\n"
              << "  submit-ml ...\n"
              << "  register-challenge ...\n"
              << "  key-rotate ...\n"
              << "  gov-param ...\n"
              << "  faucet --recipient ADDRESS --amount ATOMIC\n"
              << "  mine --producer ADDRESS --public-key HEX --signature HEX [--timestamp-ms N] [--broadcast --peers host:port,...]\n"
              << "  sync --peer host:port\n"
              << "  node --port N [--listen-host HOST] [--peers host:port,...] [--seconds N]\n"
              << "  show-tx --txid HASH\n"
              << "  backup --output FILE\n"
              << "  status\n  validate\n  self-test\n";
}

std::vector<std::string> csv_items(const std::string&s){if(s.empty())return{};auto v=split(s,',');for(auto &x:v)if(x.empty())throw std::runtime_error("empty CSV item");return v;}

void self_test(){
    std::string bogus="MERA1"+std::string(40,'0')+"00000000"; if(valid_address(bogus)) throw std::runtime_error("checksum self-test failed");
    Tx t;t.type="FAUCET";t.recipient=bogus;t.amount=1;if(merkle_root({t}).size()!=64)throw std::runtime_error("merkle self-test failed");
    if(work_reward_for_quality(100000,500000)==0)throw std::runtime_error("reward self-test failed");
    std::cout<<"STATUS=SELF_TEST_PASSED\nPROTOCOL_VERSION="<<PROTOCOL_VERSION<<"\n";
}

int main(int argc,char**argv){
    try{
        if(argc<2){usage();return 0;}
        std::string cmd=argv[1]; auto a=args_map(argc,argv); std::string data=opt(a,"data-dir","mera_data"); std::filesystem::create_directories(data);
        if(cmd=="self-test"){self_test();return 0;}
        std::string path=data+"/mera.sqlite"; std::string requested=opt(a,"network",""); State s(path,requested,opt(a,"governance-keys"),a.count("governance-threshold")?u64(a.at("governance-threshold")):0);
        if(cmd=="init"){
            std::cout<<"STATUS=initialized\nNETWORK="<<s.network<<"\nPROTOCOL_VERSION="<<PROTOCOL_VERSION<<"\nGENESIS="<<s.meta("genesis_hash")<<"\nASSET=MERA\nDECIMALS=8\nMAX_SUPPLY=100000000\nFAUCET_ENABLED="<<s.meta("faucet_enabled")<<"\nGOVERNANCE_ADDRESS="<<s.meta("governance_address")<<"\n"; return 0;
        }
        if(cmd=="balance"){auto addr=req(a,"address");auto b=s.balance(addr);std::cout<<"BALANCE_ATOMIC="<<b<<"\nBALANCE_MERA="<<std::fixed<<std::setprecision(8)<<(double)b/ATOMIC_PER_MERA<<"\n";return 0;}
        if(cmd=="nonce"){std::cout<<"NONCE="<<s.nonce(req(a,"address"))<<"\n";return 0;}
        if(cmd=="block-template"){auto b=s.block_template(req(a,"producer"),req(a,"public-key"),a.count("timestamp-ms")?u64(req(a,"timestamp-ms")):0);std::cout<<"HEIGHT="<<b.height<<"\nTIMESTAMP_MS="<<b.timestamp_ms<<"\nPREVIOUS_HASH="<<b.previous_hash<<"\nMERKLE_ROOT="<<b.merkle_root<<"\nDIFFICULTY="<<b.difficulty<<"\nTOTAL_OPS="<<b.total_ops<<"\nTOTAL_REWARD_ATOMIC="<<b.total_rewards<<"\nTX_COUNT="<<b.transactions.size()<<"\nSIGNING_MESSAGE="<<block_signing_message(b)<<"\n";for(size_t i=0;i<b.transactions.size();++i)std::cout<<"TXID_"<<i<<"="<<txid(b.transactions[i])<<"\n";return 0;}
        if(cmd=="submit-transfer"||cmd=="submit-multisig-transfer"||cmd=="submit-ml"||cmd=="register-challenge"||cmd=="key-rotate"||cmd=="gov-param"){
            Tx t;
            if(cmd=="submit-transfer"){t.type="TRANSFER";t.sender=req(a,"sender");t.recipient=req(a,"recipient");t.amount=u64(req(a,"amount"));t.fee=u64(req(a,"fee"));t.nonce=u64(req(a,"nonce"));t.public_key=req(a,"public-key");t.signature=req(a,"signature");t.payload_note=opt(a,"note");}
            if(cmd=="submit-multisig-transfer"){t.type="MULTISIG_TRANSFER";t.sender=req(a,"sender");t.recipient=req(a,"recipient");t.amount=u64(req(a,"amount"));t.fee=u64(req(a,"fee"));t.nonce=u64(req(a,"nonce"));t.multisig_threshold=u64(req(a,"threshold"));t.multisig_keys=req(a,"keys");t.multisig_sigs=req(a,"signatures");t.payload_note=opt(a,"note");}
            if(cmd=="submit-ml"){t.type="ML_WORK";t.sender=req(a,"sender");t.challenge_id=req(a,"challenge-id");t.manifest_hash=req(a,"manifest-sha256");t.dataset_hash=req(a,"dataset-sha256");t.model_hash=req(a,"model-sha256");t.arch_hash=req(a,"arch-sha256");t.ops=u64(req(a,"ops"));t.n_train=u64(req(a,"n-train"));t.n_features=u64(req(a,"n-features"));t.epochs=u64(req(a,"epochs"));t.nmse_scaled=u64(req(a,"nmse-scaled"));t.baseline_scaled=u64(req(a,"baseline-scaled"));t.work_reward=u64(req(a,"work-reward"));t.wall_ms=u64(req(a,"wall-ms"));t.lswu_micro=u64(req(a,"lswu-micro"));t.fee=u64(req(a,"fee"));t.nonce=u64(req(a,"nonce"));t.public_key=req(a,"public-key");t.signature=req(a,"signature");t.payload_note=opt(a,"note");}
            if(cmd=="register-challenge"){t.type="CHALLENGE_REGISTER";t.sender=req(a,"sender");t.challenge_id=req(a,"challenge-id");t.manifest_hash=req(a,"manifest-sha256");t.dataset_hash=req(a,"dataset-sha256");t.n_train=u64(req(a,"samples"));t.n_features=u64(req(a,"features"));t.challenge_train_fraction_ppm=u64(req(a,"train-fraction-ppm"));t.challenge_max_epochs=u64(req(a,"max-epochs"));t.challenge_budget=u64(req(a,"budget"));t.fee=u64(req(a,"fee"));t.nonce=u64(req(a,"nonce"));t.public_key=req(a,"public-key");t.signature=req(a,"signature");t.challenge_verifier=NATIVE_VERIFIER;t.challenge_metric="NMSE";t.challenge_split_rule="first_fraction";t.baseline_scaled=1000000000ULL;t.payload_note=opt(a,"note");}
            if(cmd=="key-rotate"){t.type="KEY_ROTATE";t.sender=req(a,"sender");t.new_public_key=req(a,"new-public-key");t.nonce=u64(req(a,"nonce"));t.public_key=req(a,"public-key");t.signature=req(a,"signature");}
            if(cmd=="gov-param"){t.type="GOV_PARAM";t.sender=req(a,"sender");t.gov_key=req(a,"key");t.gov_value=req(a,"value");t.gov_effective_height=u64(req(a,"effective-height"));t.nonce=u64(req(a,"nonce"));t.multisig_threshold=u64(req(a,"threshold"));t.multisig_keys=req(a,"keys");t.multisig_sigs=req(a,"signatures");}
            s.submit(t);if(a.count("broadcast")){P2P p(s,"127.0.0.1",0,csv_items(opt(a,"peers")));p.broadcast_line("TX|"+hex_encode_text(tx_wire(t)));}return 0;
        }
        if(cmd=="challenge-status"){s.print_challenge(req(a,"challenge-id"));return 0;}
        if(cmd=="faucet"){s.faucet(req(a,"recipient"),u64(req(a,"amount")));return 0;}
        if(cmd=="mine"){std::string producer=req(a,"producer"),pub=req(a,"public-key"),sig=req(a,"signature");s.mine(producer,pub,sig,a.count("timestamp-ms")?u64(req(a,"timestamp-ms")):0);if(a.count("broadcast")){P2P p(s,"127.0.0.1",0,csv_items(opt(a,"peers")));p.broadcast_line("BLOCK|"+hex_encode_text(P2P::encode_block(s.load_block(s.height()))));}return 0;}
        if(cmd=="sync"){P2P p(s,"127.0.0.1",0,csv_items(req(a,"peer")));p.sync_once();return 0;}
        if(cmd=="node"){P2P p(s,opt(a,"listen-host","0.0.0.0"),static_cast<uint16_t>(u64(req(a,"port"))),csv_items(opt(a,"peers")));p.run(a.count("seconds")?u64(a.at("seconds")):0);return 0;}
        if(cmd=="show-tx"){s.show_tx(req(a,"txid"));return 0;}
        if(cmd=="backup"){s.backup(req(a,"output"));return 0;}
        if(cmd=="status"){s.print_status();return 0;}
        if(cmd=="validate"){s.validate_chain();return 0;}
        usage();return 1;
    }catch(const std::exception&e){std::cerr<<"ERROR="<<e.what()<<"\n";return 2;}
}
