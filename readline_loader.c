#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <json-c/json.h>

// Includes for hostname and IP (local machine)
#include <limits.h>
#include <ifaddrs.h>
// #include <arpa/inet.h> // Included by netdb.h or sys/socket.h often

// Networking includes (UDP client)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>      // For getaddrinfo

#include "readline_tracker.skel.h"

#define TASK_COMM_LEN 16
#define OUTPUT_STR_LEN 480

struct data_t {
    uint32_t pid;
    uint32_t uid;
    char comm[TASK_COMM_LEN];
    char str[OUTPUT_STR_LEN];
};

// User mapping structure for uid to username
#define MAX_USERS 10000
struct user_entry {
    uint32_t uid;
    char username[128];
};

static struct user_entry g_user_map[MAX_USERS];
static int g_user_count = 0;

static volatile bool exiting = false;

// UDP Client Globals
static bool g_send_to_udp_server = false;
static char g_udp_remote_host[256];
static int g_udp_remote_port = 0;
static int g_udp_socket = -1;
static struct sockaddr_storage g_udp_serv_addr;
static socklen_t g_udp_serv_addr_len = 0;

// Configuration Globals
static char g_probe_id[256] = "";
static char g_sys_version[256] = "";
static char g_host_address[256] = "";
static char g_host_name[256] = "";


static const char *uid_to_username(uint32_t uid) {
    for (int i = 0; i < g_user_count; i++) {
        if (g_user_map[i].uid == uid) {
            return g_user_map[i].username;
        }
    }
    return "unknown";
}

static int read_passwd_file(const char *passwd_path) {
    FILE *fp = fopen(passwd_path, "r");
    if (!fp) {
        perror("Failed to open /etc/passwd");
        return -1;
    }
    
    char line[1024];
    g_user_count = 0;
    
    while (fgets(line, sizeof(line), fp) && g_user_count < MAX_USERS) {
        // /etc/passwd format: username:password:uid:gid:gecos:home:shell
        char *saveptr = NULL;
        char line_copy[1024];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        
        char *username = strtok_r(line_copy, ":", &saveptr);
        if (!username) continue;
        
        char *password = strtok_r(NULL, ":", &saveptr);
        if (!password) continue;
        
        char *uid_str = strtok_r(NULL, ":", &saveptr);
        if (!uid_str) continue;
        
        uint32_t uid = (uint32_t)atoi(uid_str);
        
        // Store the mapping
        g_user_map[g_user_count].uid = uid;
        strncpy(g_user_map[g_user_count].username, username, sizeof(g_user_map[g_user_count].username) - 1);
        g_user_map[g_user_count].username[sizeof(g_user_map[g_user_count].username) - 1] = '\0';
        g_user_count++;
    }
    
    fclose(fp);
    printf("Loaded %d user entries from /etc/passwd\n", g_user_count);
    return 0;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  --config <file>           Read configuration from <file>\n");
}

static void sig_handler(int sig) {
    exiting = true;
}

static int setup_udp_server(const char *host, int port) {
    if (g_udp_socket != -1) {
        close(g_udp_socket);
        g_udp_socket = -1;
    }

    struct addrinfo hints, *servinfo, *p;
    int rv;
    char port_str[12];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(host, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "UDP setup: getaddrinfo for %s:%d failed: %s\n", host, port, gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        g_udp_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (g_udp_socket == -1) {
            perror("UDP setup: socket error");
            continue;
        }
        memcpy(&g_udp_serv_addr, p->ai_addr, p->ai_addrlen);
        g_udp_serv_addr_len = p->ai_addrlen;
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL || g_udp_socket == -1) {
        fprintf(stderr, "UDP setup: Failed to create socket to %s:%d\n", host, port);
        return -1;
    }
    printf("UDP socket prepared for %s:%d\n", host, port);
    return 0;
}

static void send_over_udp(const char *json_data) {
    if (!g_send_to_udp_server || g_udp_socket == -1) return;
    size_t json_len = strlen(json_data);
    ssize_t sent = sendto(g_udp_socket, json_data, json_len, 0,
                          (struct sockaddr *)&g_udp_serv_addr, g_udp_serv_addr_len);
    if (sent == -1) {
        perror("UDP sendto");
        // nothing else to do, UDP is connectionless
    }
}

static void handle_event(void *cb_ctx, int cpu, void *data, __u32 data_sz) {
    const struct data_t *event = data;
    char time_buf[64];
    time_t now;
    struct tm *tm_info;

    if (data_sz < sizeof(struct data_t)) {
        fprintf(stderr, "Error: short event data received, expected %zu, got %u\n", sizeof(struct data_t), data_sz);
        return;
    }

    time(&now);
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%-m/%-d/%Y-%H:%M:%S", tm_info);

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "time", json_object_new_string(time_buf));
    json_object_object_add(jobj, "pid", json_object_new_int(event->pid));
    json_object_object_add(jobj, "uid", json_object_new_int(event->uid));
    json_object_object_add(jobj, "user", json_object_new_string(uid_to_username(event->uid)));
    json_object_object_add(jobj, "process", json_object_new_string(event->comm));
    json_object_object_add(jobj, "command", json_object_new_string(event->str));
    
    // Add configuration values to JSON
    json_object_object_add(jobj, "gl2_source_collector", json_object_new_string(g_probe_id));
    json_object_object_add(jobj, "PROBE_VER", json_object_new_string(g_sys_version));
    json_object_object_add(jobj, "host", json_object_new_string(g_host_address));
    json_object_object_add(jobj, "message", json_object_new_string(g_host_name));

    if (g_send_to_udp_server) {
        const char *json_event_string = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
        if (json_event_string) {
            send_over_udp(json_event_string);
        } else {
            fprintf(stderr, "Failed to convert event to JSON string. PID: %u, COMM: %s\n", event->pid, event->comm);
        }
    }
    json_object_put(jobj);
}

static int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (level <= LIBBPF_WARN) { return vfprintf(stderr, format, args); }
    return 0;
}

int main(int argc, char **argv) {
    struct readline_tracker_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    int opt;


    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"config",       required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    // parse --config <file>
    char *config_path = NULL;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 0: // a long option with no short equivalent
                if (strcmp(long_options[option_index].name, "config") == 0) {
                    config_path = optarg;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    if (!config_path) {
        fprintf(stderr, "Error: configuration file must be specified with --config\n");
        print_usage(argv[0]);
        return 1;
    }
    // read configuration
    {
        FILE *cf = fopen(config_path, "r");
        if (!cf) { perror("Unable to open config file"); return 1; }
        char line[512];
        while (fgets(line, sizeof(line), cf)) {
            char *p = line;
            // trim leading whitespace
            while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
            if (*p == '\0' || *p == '#' || *p == '\n') continue;
            // expect key=value
            char *eq = strchr(p, '=');
            if (!eq) continue;
            *eq = '\0';
            char *key = p;
            char *value = eq + 1;
            // trim trailing whitespace from key
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t')) { *end = '\0'; end--; }
            // trim whitespace and newline from value
            end = value + strlen(value) - 1;
            while (end > value && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) { *end = '\0'; end--; }
            if (strcmp(key, "exp-domain") == 0) {
                // parse host:port
                char *colon = strchr(value, ':');
                if (!colon) {
                    fprintf(stderr, "config: exp-domain value must be IP:PORT\n");
                    fclose(cf);
                    return 1;
                }
                *colon = '\0';
                strncpy(g_udp_remote_host, value, sizeof(g_udp_remote_host)-1);
                g_udp_remote_host[sizeof(g_udp_remote_host)-1] = '\0';
                g_udp_remote_port = atoi(colon + 1);
                g_send_to_udp_server = true;
            } else if (strcmp(key, "probe-id") == 0) {
                strncpy(g_probe_id, value, sizeof(g_probe_id)-1);
                g_probe_id[sizeof(g_probe_id)-1] = '\0';
            } else if (strcmp(key, "sys-version") == 0) {
                strncpy(g_sys_version, value, sizeof(g_sys_version)-1);
                g_sys_version[sizeof(g_sys_version)-1] = '\0';
            } else if (strcmp(key, "host-address") == 0) {
                strncpy(g_host_address, value, sizeof(g_host_address)-1);
                g_host_address[sizeof(g_host_address)-1] = '\0';
            } else if (strcmp(key, "host-name") == 0) {
                strncpy(g_host_name, value, sizeof(g_host_name)-1);
                g_host_name[sizeof(g_host_name)-1] = '\0';
            }
        }
        fclose(cf);
    }

    if (!g_send_to_udp_server) {
        fprintf(stderr, "Error: UDP endpoint not configured in config file.\n");
        return 1;
    }

    if (g_send_to_udp_server) {
        printf("Preparing to send data to UDP server: %s:%d\n", g_udp_remote_host, g_udp_remote_port);
        if (setup_udp_server(g_udp_remote_host, g_udp_remote_port) != 0) {
            fprintf(stderr, "Failed to configure UDP destination\n");
            return 1;
        }
    }

    // Read /etc/passwd to map uid to usernames
    if (read_passwd_file("/etc/passwd") != 0) {
        fprintf(stderr, "Warning: Failed to read /etc/passwd, user field will show 'unknown'\n");
    }

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) { perror("setrlimit(RLIMIT_MEMLOCK)"); return 1; }

    libbpf_set_print(print_libbpf_log);
    skel = readline_tracker_bpf__open();
    if (!skel) { fprintf(stderr, "Failed to open BPF skeleton\n"); goto cleanup; }
    err = readline_tracker_bpf__load(skel);
    if (err) { fprintf(stderr, "Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err)); goto cleanup; }
    err = readline_tracker_bpf__attach(skel);
    if (err) { fprintf(stderr, "Failed to attach BPF skeleton: %d (%s)\n", err, strerror(-err)); goto cleanup; }

    printf("eBPF program attached. Waiting for events...\n");
    if (g_send_to_udp_server) printf("UDP output: %s:%d\n", g_udp_remote_host, g_udp_remote_port);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) { err = -errno; fprintf(stderr, "Failed to create perf buffer: %d (%s)\n", err, strerror(-err)); goto cleanup; }

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "Error polling perf buffer: %d (%s)\n", err, strerror(-err)); break; }
        err = 0;
    }

cleanup:
    if (pb) perf_buffer__free(pb);
    if (skel) readline_tracker_bpf__destroy(skel);
    if (g_udp_socket != -1) {
        close(g_udp_socket);
        g_udp_socket = -1;
    }
    printf("\nExiting.\n");
    return -err < 0 ? -err : 0;
}
