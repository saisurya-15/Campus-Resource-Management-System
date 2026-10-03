#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <optional>
#include <random>
#include <regex>

#include "httplib.h"
#include "sqlite3.h"
#include "json.hpp"

using json = nlohmann::json;

// -------------------------------------------------------------------
// 1. Key management
// -------------------------------------------------------------------
std::string master_key;
std::string api_key;

std::string generate_random_key() {
    static const char hex_chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::string key;
    for (int i = 0; i < 32; ++i) {
        key += hex_chars[dis(gen)];
    }
    return key;
}

void load_or_generate_keys(const std::string& config_path) {
    std::ifstream ifs(config_path);
    if (ifs.good()) {
        json config;
        try {
            ifs >> config;
            master_key = config.value("master_key", "");
            api_key = config.value("api_key", "");
            if (!master_key.empty() && !api_key.empty()) {
                std::cout << "\033[1;34m[INFO]\033[0m Keys loaded from " << config_path << std::endl;
                return;
            }
        } catch (...) {}
    }
    ifs.close();

    master_key = generate_random_key();
    api_key = generate_random_key();

    json config;
    config["master_key"] = master_key;
    config["api_key"] = api_key;

    std::ofstream ofs(config_path);
    if (ofs) {
        ofs << config.dump(4);
        std::cout << "\033[1;34m[INFO]\033[0m Generated new keys, saved to " << config_path << std::endl;
    } else {
        std::cerr << "\033[1;31m[ERROR]\033[0m Failed to write keys file!" << std::endl;
    }
}

// -------------------------------------------------------------------
// 2. Origin whitelist (dynamic)
// -------------------------------------------------------------------
std::vector<std::string> allowed_origins_list;
std::string origins_file = "allow-origin.json";

void save_origins_to_file() {
    json data(allowed_origins_list);
    std::ofstream ofs(origins_file);
    if (ofs) ofs << data.dump(4);
}

void load_allowed_origins(const std::string& filepath) {
    std::ifstream ifs(filepath);
    if (ifs.good()) {
        try {
            json data;
            ifs >> data;
            if (data.is_array()) {
                for (const auto& item : data) {
                    if (item.is_string())
                        allowed_origins_list.push_back(item.get<std::string>());
                }
            }
        } catch (...) {}
    }
    ifs.close();

    if (allowed_origins_list.empty()) {
        save_origins_to_file(); // create empty file
    }
}

bool is_origin_allowed(const std::string& origin) {
    // Always allow localhost and 127.0.0.1 (any port, http only)
    if (origin.find("http://localhost") == 0 || origin.find("http://127.0.0.1") == 0) {
        return true;
    }
    for (const auto& allowed : allowed_origins_list) {
        if (origin == allowed) return true;
    }
    return false;
}

void add_allowed_origin(const std::string& origin) {
    for (const auto& o : allowed_origins_list) {
        if (o == origin) return; // avoid duplicates
    }
    allowed_origins_list.push_back(origin);
    save_origins_to_file();
}

bool remove_allowed_origin(const std::string& origin) {
    auto it = std::find(allowed_origins_list.begin(), allowed_origins_list.end(), origin);
    if (it != allowed_origins_list.end()) {
        allowed_origins_list.erase(it);
        save_origins_to_file();
        return true;
    }
    return false;
}

// -------------------------------------------------------------------
// 3. Console logging utilities
// -------------------------------------------------------------------
void log_request(const httplib::Request &req) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    
    std::cout << "\033[1;36m[" << ss.str() << "]\033[0m "
              << "\033[1;32m" << req.method << "\033[0m "
              << req.path;
    if (!req.body.empty())
        std::cout << " body=" << req.body;
    std::cout << std::endl;
}

void log_info(const std::string &msg) {
    std::cout << "\033[1;34m[INFO]\033[0m " << msg << std::endl;
}

void log_error(const std::string &msg) {
    std::cerr << "\033[1;31m[ERROR]\033[0m " << msg << std::endl;
}

// -------------------------------------------------------------------
// 4. Authentication helper
// -------------------------------------------------------------------
enum KeyType { KEY_NONE, KEY_API, KEY_MASTER };

KeyType authenticate_request(const httplib::Request &req) {
    std::string key;
    if (req.has_header("X-LC-Key")) {
        key = req.get_header_value("X-LC-Key");
    }
    if (key.empty() && req.method == "GET" && req.path == "/") {
        if (req.has_param("apikey")) key = req.get_param_value("apikey");
        else if (req.has_param("masterkey")) key = req.get_param_value("masterkey");
    }
    if (key.empty()) return KEY_NONE;
    if (key == master_key) return KEY_MASTER;
    if (key == api_key) return KEY_API;
    return KEY_NONE;
}

std::map<std::string, int> request_counters;

void increment_request_counter(const std::string &name) {
    request_counters[name]++;
}

// -------------------------------------------------------------------
// 5. File loading helper
// -------------------------------------------------------------------
std::string load_file_content(const std::string& filepath) {
    std::ifstream ifs(filepath);
    if (!ifs.good()) {
        return "<html><body><h1>Error: File not found</h1></body></html>";
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

// -------------------------------------------------------------------
// 6. Database wrapper (SQLite) �C with order / limit / offset support
// -------------------------------------------------------------------
class SimpleDB {
public:
    SimpleDB(const std::string &db_path = "data.db") {
        int rc = sqlite3_open(db_path.c_str(), &db_);
        if (rc) {
            log_error("Cannot open database: " + std::string(sqlite3_errmsg(db_)));
            db_ = nullptr;
        } else {
            log_info("Database connected: " + db_path);
        }
    }

    ~SimpleDB() {
        if (db_) sqlite3_close(db_);
    }

    std::vector<std::string> get_all_tables() {
        std::vector<std::string> tables;
        if (!db_) return tables;
        const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (name != "sqlite_sequence" && name != "sqlite_stat1" && name != "sqlite_stat4")
                    tables.push_back(name);
            }
        }
        sqlite3_finalize(stmt);
        return tables;
    }

    bool create_table(const std::string &table) {
        std::string sql = 
            "CREATE TABLE IF NOT EXISTS \"" + table + "\" ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  objectId TEXT UNIQUE,"
            "  createdAt TEXT,"
            "  updatedAt TEXT,"
            "  data TEXT"
            ");";
        return execute(sql);
    }

    std::string insert(const std::string &table, const json &data) {
        if (!db_) return "";
        create_table(table);
        std::string obj_id = generate_object_id();
        std::string now = current_time();
        std::string json_data = data.dump();

        std::string sql = 
            "INSERT INTO \"" + table + "\" (objectId, createdAt, updatedAt, data) "
            "VALUES (?, ?, ?, ?);";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            log_error("Insert prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return "";
        }
        sqlite3_bind_text(stmt, 1, obj_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, now.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, now.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, json_data.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            log_error("Insert execution failed: " + std::string(sqlite3_errmsg(db_)));
            sqlite3_finalize(stmt);
            return "";
        }
        sqlite3_finalize(stmt);
        log_info("Insert succeeded: " + table + " -> " + obj_id);
        return obj_id;
    }

    // Enhanced select with order, limit, offset
    std::vector<json> select(const std::string &table,
                             const std::string &where_clause = "",
                             const std::string &order_by = "",
                             int limit = 0,
                             int offset = 0) {
        std::vector<json> result;
        if (!db_) return result;
        create_table(table);
        std::string sql = "SELECT objectId, createdAt, updatedAt, data FROM \"" + table + "\"";
        if (!where_clause.empty()) sql += " WHERE " + where_clause;
        if (!order_by.empty()) sql += " ORDER BY " + order_by;
        if (limit > 0) {
            sql += " LIMIT " + std::to_string(limit);
            if (offset > 0) sql += " OFFSET " + std::to_string(offset);
        }
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            log_error("Select prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return result;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json obj;
            obj["objectId"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            obj["createdAt"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
            obj["updatedAt"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
            std::string data_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            obj["data"] = json::parse(data_str);
            result.push_back(obj);
        }
        sqlite3_finalize(stmt);
        log_info("Query: " + table + " returned " + std::to_string(result.size()) + " record(s)");
        return result;
    }

    std::optional<json> select_one(const std::string &table, const std::string &objectId) {
        if (!db_) return std::nullopt;
        create_table(table);
        std::string sql = "SELECT objectId, createdAt, updatedAt, data FROM \"" + table + "\" WHERE objectId = ? LIMIT 1;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            log_error("SelectOne prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return std::nullopt;
        }
        sqlite3_bind_text(stmt, 1, objectId.c_str(), -1, SQLITE_STATIC);
        std::optional<json> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            json obj;
            obj["objectId"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            obj["createdAt"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
            obj["updatedAt"] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
            std::string data_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            obj["data"] = json::parse(data_str);
            result = obj;
        }
        sqlite3_finalize(stmt);
        return result;
    }

    int count_rows(const std::string &table) {
        if (!db_) return 0;
        create_table(table);
        std::string sql = "SELECT COUNT(*) FROM \"" + table + "\";";
        sqlite3_stmt *stmt;
        int count = 0;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                count = sqlite3_column_int(stmt, 0);
            }
        }
        sqlite3_finalize(stmt);
        return count;
    }

    bool update(const std::string &table, const std::string &objectId, const json &data) {
        if (!db_) return false;
        std::string now = current_time();
        std::string sql = 
            "UPDATE \"" + table + "\" SET updatedAt = ?, data = ? WHERE objectId = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            log_error("Update prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return false;
        }
        std::string json_data = data.dump();
        sqlite3_bind_text(stmt, 1, now.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, json_data.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, objectId.c_str(), -1, SQLITE_STATIC);

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        if (ok) log_info("Update succeeded: " + table + " -> " + objectId);
        else log_error("Update failed: " + std::string(sqlite3_errmsg(db_)));
        sqlite3_finalize(stmt);
        return ok;
    }

    bool remove(const std::string &table, const std::string &objectId) {
        if (!db_) return false;
        std::string sql = "DELETE FROM \"" + table + "\" WHERE objectId = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            log_error("Delete prepare failed: " + std::string(sqlite3_errmsg(db_)));
            return false;
        }
        sqlite3_bind_text(stmt, 1, objectId.c_str(), -1, SQLITE_STATIC);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        if (ok) log_info("Delete succeeded: " + table + " -> " + objectId);
        else log_error("Delete failed: " + std::string(sqlite3_errmsg(db_)));
        sqlite3_finalize(stmt);
        return ok;
    }

private:
    sqlite3 *db_ = nullptr;

    bool execute(const std::string &sql) {
        char *err = nullptr;
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            log_error("SQL execution failed: " + std::string(err));
            sqlite3_free(err);
            return false;
        }
        return true;
    }

    std::string generate_object_id() {
        static int counter = 0;
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        return std::to_string(now) + "-" + std::to_string(++counter);
    }

    std::string current_time() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }
};

// Helper: parse order parameter into safe SQL ORDER BY clause
std::string build_order_clause(const std::string& order_param) {
    if (order_param.empty()) return "";
    std::stringstream ss;
    std::string field;
    std::istringstream stream(order_param);
    bool first = true;
    while (std::getline(stream, field, ',')) {
        if (field.empty()) continue;
        bool desc = false;
        if (field[0] == '-') {
            desc = true;
            field = field.substr(1);
        }
        // Allow alphanumeric, underscore, hyphen, and dot (for nested fields)
        if (field.empty() || !std::regex_match(field, std::regex("^[a-zA-Z0-9_.-]+$"))) {
            continue; // skip invalid field
        }
        // Map system fields to column names, otherwise json_extract from data
        std::string col_expr;
        if (field == "createdAt" || field == "updatedAt") {
            col_expr = "\"" + field + "\"";
        } else {
            col_expr = "json_extract(data, '$." + field + "')";
        }
        if (!first) ss << ", ";
        ss << col_expr << (desc ? " DESC" : " ASC");
        first = false;
    }
    return ss.str();
}

// -------------------------------------------------------------------
// 6. Main function �� HTTP server with CORS, Origin whitelist, and order/limit/skip support
// -------------------------------------------------------------------
int main() {
    load_or_generate_keys("keys.json");
    load_allowed_origins("allow-origin.json");

    SimpleDB db;
    httplib::Server svr;

    svr.set_pre_routing_handler([](const httplib::Request &req, httplib::Response &res) {
        std::string origin = req.get_header_value("Origin");
        if (!origin.empty()) {
            if (!is_origin_allowed(origin)) {
                res.status = 403;
                res.set_content("Forbidden: Origin not allowed.", "text/plain");
                return httplib::Server::HandlerResponse::Handled;
            }
            res.set_header("Access-Control-Allow-Origin", origin);
            res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type, X-LC-Key");
            res.set_header("Access-Control-Max-Age", "86400");
        }

        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }

        log_request(req);

        KeyType key = authenticate_request(req);
        if (key == KEY_NONE) {
            res.status = 401;
            res.set_content("Unauthorized: Missing or invalid X-LC-Key header or URL parameter.", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }

        std::string counter_name = std::string(req.method) + " " + req.path;
        increment_request_counter(counter_name);

        if (req.method == "DELETE" && key != KEY_MASTER) {
            res.status = 403;
            res.set_content("Forbidden: Master key required for deletion.", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (req.method == "POST" && req.path == "/origins" && key != KEY_MASTER) {
            res.status = 403;
            res.set_content("Forbidden: Master key required to modify origins.", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // HTML UI
    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(load_file_content("index.html"), "text/html");
    });

    // Table list
    svr.Get("/tables", [&](const httplib::Request &, httplib::Response &res) {
        json resp;
        resp["tables"] = db.get_all_tables();
        res.set_content(resp.dump(), "application/json");
    });

    // Usage statistics
    svr.Get("/stats", [&](const httplib::Request &, httplib::Response &res) {
        json resp;
        auto tables = db.get_all_tables();
        int totalObjects = 0;
        json counts = json::object();
        for (const auto &table : tables) {
            int cnt = db.count_rows(table);
            counts[table] = cnt;
            totalObjects += cnt;
        }
        resp["tableCount"] = tables.size();
        resp["objectCount"] = totalObjects;
        resp["countsByTable"] = counts;
        json counterJson = json::object();
        for (const auto &entry : request_counters) {
            counterJson[entry.first] = entry.second;
        }
        resp["requestCounts"] = counterJson;
        res.set_content(resp.dump(), "application/json");
    });

    // Origins CRUD
    svr.Get("/origins", [](const httplib::Request &, httplib::Response &res) {
        json arr(allowed_origins_list);
        res.set_content(arr.dump(), "application/json");
    });

    svr.Post("/origins", [](const httplib::Request &req, httplib::Response &res) {
        json body = json::parse(req.body);
        std::string origin = body.value("origin", "");
        if (origin.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"origin required\"}", "application/json");
            return;
        }
        add_allowed_origin(origin);
        res.set_content("{\"status\":\"ok\"}", "application/json");
    });

    svr.Delete("/origins", [](const httplib::Request &req, httplib::Response &res) {
        std::string origin = req.get_param_value("origin");
        if (origin.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"origin parameter required\"}", "application/json");
            return;
        }
        if (remove_allowed_origin(origin)) {
            res.set_content("{\"status\":\"deleted\"}", "application/json");
        } else {
            res.status = 404;
            res.set_content("{\"error\":\"origin not found\"}", "application/json");
        }
    });

    // REST API for classes
    svr.Post(R"(/classes/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        std::string table = req.matches[1];
        try {
            json data = json::parse(req.body);
            std::string objectId = db.insert(table, data);
            if (objectId.empty()) {
                res.status = 500;
                res.set_content(R"({"error":"Insert failed"})", "application/json");
                return;
            }
            auto inserted = db.select_one(table, objectId);
            if (!inserted.has_value()) {
                res.status = 500;
                res.set_content(R"({"error":"Insert succeeded but record not found"})", "application/json");
                return;
            }
            json resp;
            resp["objectId"] = objectId;
            resp["createdAt"] = inserted->value("createdAt", "");
            res.status = 201;
            res.set_content(resp.dump(), "application/json");
        } catch (const std::exception &e) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON format"})", "application/json");
        }
    });

    svr.Get(R"(/classes/([^/]+)/(\S+))", [&](const httplib::Request &req, httplib::Response &res) {
        std::string table = req.matches[1];
        std::string objId = req.matches[2];
        auto result = db.select_one(table, objId);
        if (!result.has_value()) {
            res.status = 404;
            res.set_content(R"({"error":"Object not found"})", "application/json");
        } else {
            res.set_content(result->dump(), "application/json");
        }
    });

    svr.Get(R"(/classes/([^/]+))", [&](const httplib::Request &req, httplib::Response &res) {
        std::string table = req.matches[1];
        // Parse query parameters for ordering, limit, skip
        std::string order_by;
        if (req.has_param("order")) {
            order_by = build_order_clause(req.get_param_value("order"));
        }
        int limit = 0;
        if (req.has_param("limit")) {
            try { limit = std::stoi(req.get_param_value("limit")); } catch(...) {}
        }
        int skip = 0;
        if (req.has_param("skip")) {
            try { skip = std::stoi(req.get_param_value("skip")); } catch(...) {}
        }
        auto results = db.select(table, "", order_by, limit, skip);
        json resp;
        resp["results"] = results;
        res.set_content(resp.dump(), "application/json");
    });

    svr.Put(R"(/classes/([^/]+)/(\S+))", [&](const httplib::Request &req, httplib::Response &res) {
        std::string table = req.matches[1];
        std::string objId = req.matches[2];
        try {
            json data = json::parse(req.body);
            if (db.update(table, objId, data)) {
                auto updated = db.select_one(table, objId);
                if (updated.has_value()) {
                    res.set_content(updated->dump(), "application/json");
                } else {
                    res.status = 500;
                    res.set_content(R"({"error":"Updated but record failed to load"})", "application/json");
                }
            } else {
                res.status = 404;
                res.set_content(R"({"error":"Update failed, object may not exist"})", "application/json");
            }
        } catch (const std::exception &e) {
            res.status = 400;
            res.set_content(R"({"error":"Invalid JSON format"})", "application/json");
        }
    });

    svr.Delete(R"(/classes/([^/]+)/(\S+))", [&](const httplib::Request &req, httplib::Response &res) {
        std::string table = req.matches[1];
        std::string objId = req.matches[2];
        if (db.remove(table, objId)) {
            res.set_content(R"({"message":"Deleted successfully"})", "application/json");
        } else {
            res.status = 404;
            res.set_content(R"({"error":"Delete failed, object may not exist"})", "application/json");
        }
    });

    const std::string host = "127.0.0.1";
    const int port = 12345;
    log_info("Server starting...");
    if (svr.listen(host, port)) {
        // Print optimized startup info
        std::cout << "\n\033[1;32m==========================================\033[0m\n";
        std::cout << "Server started. Access URLs:\n";
        std::cout << "  Console (API Key) : http://127.0.0.1:12345/?apikey=" << api_key << "\n";
        std::cout << "  Console (Master Key): http://127.0.0.1:12345/?masterkey=" << master_key << "\n";
        std::cout << "\033[1;32m==========================================\033[0m\n";
    } else {
        log_error("Failed to start server, port " + std::to_string(port) + " may be in use");
        return 1;
    }

    return 0;
}
