#ifdef _WIN32
    #include <winsock2.h>   // Winsock2 for Windows Sockets
    #include <ws2tcpip.h>   // For sockaddr_in, inet_pton, etc.
    #include <windows.h>    // For CreateDirectory, Sleep
    #include <direct.h>     // For _mkdir
    #include <sys/types.h>  // For _stat64 on Windows (MinGW)
    #include <sys/stat.h>   // For _stat64 on Windows (MinGW)
    #define close(s) closesocket(s) // Map close to closesocket for Windows
    #define snprintf _snprintf      // Use _snprintf for Windows compatibility
    #pragma comment(lib, "ws2_32.lib") // Link with ws2_32.lib
#else
    #include <unistd.h>         // POSIX operating system API (close, unlink)
    #include <sys/socket.h>     // Socket programming functions (socket, bind, listen, accept, send, recv)
    #include <netinet/in.h>     // Internet domain addresses (sockaddr_in, htons, htonl)
    #include <arpa/inet.h>      // Functions for manipulating IP addresses (inet_ntoa)
    #include <sys/stat.h>       // For mkdir, stat
    #include <dirent.h>         // For opendir, readdir, closedir
#endif

#include <stdio.h>          // Standard I/O functions (printf, perror, fopen, fclose, fwrite)
#include <stdlib.h>         // Standard library functions (exit, malloc, free)
#include <string.h>         // String manipulation functions (strlen, strcpy, memset, strncmp, strtok)
#include <pthread.h>        // POSIX threads for concurrency (available on MinGW/WSL for Windows too)
#include <errno.h>          // For errno

// Define the port number the server will listen on
#define PORT 8080
// Define the maximum number of pending connections in the listen queue
#define MAX_PENDING_CONNECTIONS 5
// Define the buffer size for messages and file chunks
#define BUFFER_SIZE 1024
// Define the maximum number of clients the server can handle
#define MAX_CLIENTS 10
// Define the directory where received files will be stored
#define UPLOAD_DIR "server_files/"

// Max nickname length (must match client)
#define NICKNAME_MAX_LEN 32
// Max password length (must match client)
#define PASSWORD_MAX_LEN 32

// --- Client Structure ---
typedef struct {
    int sock;
    char nickname[NICKNAME_MAX_LEN + 1];
    int authenticated; // 0 for not authenticated, 1 for authenticated
} client_info_t;

// Array to store connected client information
client_info_t clients[MAX_CLIENTS];
// Mutex to protect access to the clients array and other shared resources
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- Authentication Credentials (Simple for demonstration) ---
// In a real application, these would be stored securely (e.g., hashed in a database)
// Now, AUTH_USERNAME is effectively any username provided by client, AUTH_PASSWORD is the shared secret.
#define AUTH_PASSWORD "pass" // This is the shared password all clients must use

// --- Helper Functions ---

// Function to add a new client socket to the array
void add_client(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock == 0) { // Find the first available slot (0 indicates empty)
            clients[i].sock = sock;
            memset(clients[i].nickname, 0, sizeof(clients[i].nickname)); // Clear nickname
            clients[i].authenticated = 0; // Not authenticated initially
            printf("Client added: socket %d at index %d\n", sock, i);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to remove a client socket from the array
void remove_client(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock == sock) { // Find the client's socket
            printf("Client removed: socket %d, nickname '%s'\n", sock, clients[i].nickname);
            clients[i].sock = 0; // Mark the slot as empty
            memset(clients[i].nickname, 0, sizeof(clients[i].nickname)); // Clear nickname
            clients[i].authenticated = 0; // Reset auth status
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to get client nickname by socket ID
const char* get_client_nickname(int sock) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock == sock) {
            pthread_mutex_unlock(&clients_mutex);
            return clients[i].nickname;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return "Unknown";
}

// Function to set client nickname and authentication status
void set_client_auth_status(int sock, const char* nickname, int authenticated) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock == sock) {
            strncpy(clients[i].nickname, nickname, NICKNAME_MAX_LEN);
            clients[i].nickname[NICKNAME_MAX_LEN] = '\0';
            clients[i].authenticated = authenticated;
            printf("Client %d (Nickname: %s) authentication status: %d\n", sock, clients[i].nickname, authenticated);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}


// Function to send a message to all connected clients except the sender (if sender_sock is valid)
// If sender_sock is 0, it broadcasts to all clients.
void broadcast_message(char *message, int sender_sock) {
    pthread_mutex_lock(&clients_mutex);
    // Find the sender's index first to ensure explicit skipping
    int sender_idx = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock == sender_sock) {
            sender_idx = i;
            break;
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock != 0 && clients[i].authenticated == 1) {
            // Skip the sender's own socket
            if (i == sender_idx) {
                continue; // Skip sending to the sender
            }

            if (send(clients[i].sock, message, strlen(message), 0) < 0) {
                perror("send failed (broadcast)");
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to safely receive a specified number of bytes
ssize_t recv_all(int sock, void *buffer, size_t length) {
    size_t total_received = 0;
    ssize_t bytes_received;
    char *buf_ptr = (char *)buffer;

    while (total_received < length) {
        bytes_received = recv(sock, buf_ptr + total_received, length - total_received, 0);
        if (bytes_received <= 0) {
            return bytes_received; // 0 indicates connection closed, -1 indicates error
        }
        total_received += bytes_received;
    }
    return total_received;
}

// Function to safely send a specified number of bytes
ssize_t send_all(int sock, const void *buffer, size_t length) {
    size_t total_sent = 0;
    ssize_t bytes_sent;
    const char *buf_ptr = (const char *)buffer;

    while (total_sent < length) {
        bytes_sent = send(sock, buf_ptr + total_sent, length - total_sent, 0);
        if (bytes_sent <= 0) {
            return bytes_sent; // 0 indicates connection closed, -1 indicates error
        }
        total_sent += bytes_sent;
    }
    return total_sent;
}

// --- File Listing Function ---
void send_file_list(int client_sock) {
    char file_list_message[BUFFER_SIZE * 2] = {0}; // Larger buffer for list
    strcat(file_list_message, "SERVER_FILES:\n");

#ifdef _WIN32
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA(UPLOAD_DIR "*", &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        snprintf(file_list_message, sizeof(file_list_message), "SERVER_FILES: No files found or directory error.\n");
        send(client_sock, file_list_message, strlen(file_list_message), 0);
        return;
    }

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            // Append filename to the list
            strcat(file_list_message, findFileData.cFileName);
            strcat(file_list_message, "\n");
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);
    FindClose(hFind);
#else // Linux/macOS
    DIR *d;
    struct dirent *dir;
    d = opendir(UPLOAD_DIR);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) { // Check if it's a regular file
                // Append filename to the list
                strcat(file_list_message, dir->d_name);
                strcat(file_list_message, "\n");
            }
        }
        closedir(d);
    } else {
        snprintf(file_list_message, sizeof(file_list_message), "SERVER_FILES: No files found or directory error.\n");
        send(client_sock, file_list_message, strlen(file_list_message), 0);
        return;
    }
#endif

    // Send the compiled list to the requesting client
    send(client_sock, file_list_message, strlen(file_list_message), 0);
}

// Function to send a list of connected clients to a specific client
void send_client_list(int client_sock) {
    char client_list_message[BUFFER_SIZE * 2] = {0};
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock != 0 && clients[i].authenticated == 1) { // Only list authenticated clients
            char client_entry[NICKNAME_MAX_LEN + 20]; // Sufficient space for nickname and socket info
            snprintf(client_entry, sizeof(client_entry), "- %s (Socket: %d)\n", clients[i].nickname, clients[i].sock);
            strcat(client_list_message, client_entry);
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    char final_message[BUFFER_SIZE * 2 + 20]; // Buffer for "CLIENT_LIST: " + list
    snprintf(final_message, sizeof(final_message), "CLIENT_LIST: %s", client_list_message);
    send(client_sock, final_message, strlen(final_message), 0);
}


// --- Thread Function to Handle Clients ---
void *handle_client(void *socket_desc) {
    int sock = *(int*)socket_desc;
    int read_size;
    char client_message[BUFFER_SIZE];
    char formatted_message[BUFFER_SIZE + 100]; // Increased buffer for messages

    printf("New client connected: socket %d\n", sock);

    // Get client info for this socket
    client_info_t *current_client = NULL;
    pthread_mutex_lock(&clients_mutex);
    for(int i=0; i<MAX_CLIENTS; ++i) {
        if(clients[i].sock == sock) {
            current_client = &clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    if (current_client == NULL) { // Should not happen if add_client worked
        printf("Error: Could not find client info for socket %d\n", sock);
        close(sock);
        free(socket_desc);
        return NULL;
    }

    // Main loop for receiving messages and file data from the client
    while ((read_size = recv(sock, client_message, BUFFER_SIZE - 1, 0)) > 0) {
        client_message[read_size] = '\0'; // Null-terminate the received string

        // --- Handle Authentication Command (Must be first for unauthenticated clients) ---
        if (strncmp(client_message, "/auth ", 6) == 0) {
            char *auth_cmd = client_message + 6;
            char *nickname_str = strtok(auth_cmd, " ");
            char *password_str = strtok(NULL, " ");

            if (nickname_str && password_str &&
                strcmp(password_str, AUTH_PASSWORD) == 0) { // ONLY check password
                set_client_auth_status(sock, nickname_str, 1); // Use client's provided nickname
                send(sock, "AUTH_SUCCESS", strlen("AUTH_SUCCESS"), 0);
                char join_msg[BUFFER_SIZE];
                snprintf(join_msg, sizeof(join_msg), "SERVER: %s has joined the chat.", nickname_str);
                broadcast_message(join_msg, sock); // Announce join to others
            } else {
                send(sock, "AUTH_FAILURE", strlen("AUTH_FAILURE"), 0);
                printf("Client %d failed authentication (Nickname: %s, Password: %s)\n", sock, nickname_str ? nickname_str : "N/A", password_str ? password_str : "N/A");
                // For security, you might want to close the connection immediately on failure
                // For this example, we let the client exit.
            }
            memset(client_message, 0, BUFFER_SIZE);
            continue; // Process next message
        }

        // --- Rest of the commands require authentication ---
        if (current_client->authenticated == 0) {
            send(sock, "SERVER: Not authenticated. Please use /auth <nickname> <password>.", strlen("SERVER: Not authenticated. Please use /auth <nickname> <password>."), 0);
            memset(client_message, 0, BUFFER_SIZE);
            continue;
        }

        // --- Handle File Upload Command ---
        if (strncmp(client_message, "/sendfile ", 10) == 0) {
            char *token;
            char *filename_str;
            char *filesize_str;
            long file_size;
            char file_path[256];
            FILE *fp;
            ssize_t bytes_received_total = 0;
            ssize_t current_bytes_received;
            char file_buffer[BUFFER_SIZE];

            char temp_message[BUFFER_SIZE];
            strcpy(temp_message, client_message);

            token = strtok(temp_message, " "); // "/sendfile"
            filename_str = strtok(NULL, " "); // <filename>
            filesize_str = strtok(NULL, " "); // <filesize>

            if (filename_str == NULL || filesize_str == NULL) {
                snprintf(formatted_message, sizeof(formatted_message), "SERVER: Invalid /sendfile command format from %s.\n", current_client->nickname);
                send(sock, formatted_message, strlen(formatted_message), 0);
                continue;
            }

            file_size = atol(filesize_str);
            if (file_size <= 0) {
                snprintf(formatted_message, sizeof(formatted_message), "SERVER: Invalid file size for transfer from %s.\n", current_client->nickname);
                send(sock, formatted_message, strlen(formatted_message), 0);
                continue;
            }

            snprintf(file_path, sizeof(file_path), "%s%s", UPLOAD_DIR, filename_str); // Save with original name
            printf("Attempting to receive file '%s' (size %ld bytes) from %s to path: %s\n", filename_str, file_size, current_client->nickname, file_path);

            fp = fopen(file_path, "wb");
            if (fp == NULL) {
                perror("Server: Failed to open file for writing");
                snprintf(formatted_message, sizeof(formatted_message), "SERVER: Failed to open file '%s' for saving on server.\n", filename_str);
                send(sock, formatted_message, strlen(formatted_message), 0);
                continue;
            }

            // Receive file data
            while (bytes_received_total < file_size) {
                size_t bytes_to_read = BUFFER_SIZE;
                if (file_size - bytes_received_total < BUFFER_SIZE) {
                    bytes_to_read = file_size - bytes_received_total;
                }

                current_bytes_received = recv_all(sock, file_buffer, bytes_to_read);

                if (current_bytes_received <= 0) {
                    perror("Server: Error receiving file data or client disconnected during transfer");
                    fclose(fp);
                    remove(file_path); // Use remove() for cross-platform delete
                    snprintf(formatted_message, sizeof(formatted_message), "SERVER: File transfer failed for '%s' from %s.\n", filename_str, current_client->nickname);
                    send(sock, formatted_message, strlen(formatted_message), 0);
                    goto end_file_upload;
                }

                if (fwrite(file_buffer, 1, current_bytes_received, fp) != current_bytes_received) {
                    perror("Server: Error writing file data to disk");
                    fclose(fp);
                    remove(file_path);
                    snprintf(formatted_message, sizeof(formatted_message), "SERVER: Failed to write file '%s' from %s.\n", filename_str, current_client->nickname);
                    send(sock, formatted_message, strlen(formatted_message), 0);
                    goto end_file_upload;
                }
                bytes_received_total += current_bytes_received;
                // printf("Received %ld/%ld bytes for '%s' from Client %d\n", bytes_received_total, file_size, filename_str, sock);
            }

            fclose(fp);
            printf("Successfully received file '%s' (size %ld bytes) from %s.\n", filename_str, file_size, current_client->nickname);

            snprintf(formatted_message, sizeof(formatted_message), "FILE_UPLOADED: %s uploaded '%s' (%ld bytes).", current_client->nickname, filename_str, file_size);
            broadcast_message(formatted_message, 0); // Broadcast to all, including sender for confirmation

            end_file_upload:;
            memset(client_message, 0, BUFFER_SIZE);
        }
        // --- Handle File Download Request Command ---
        else if (strncmp(client_message, "/getfile ", 9) == 0) {
            char *requested_filename = client_message + 9;
            char file_path[256];
            FILE *fp;
            long file_size;
            char file_buffer[BUFFER_SIZE];
            ssize_t bytes_read;
            char response_header[BUFFER_SIZE];

            snprintf(file_path, sizeof(file_path), "%s%s", UPLOAD_DIR, requested_filename);

            // Get file size
            #ifdef _WIN32
                struct _stat64 file_stat;
                if (_stat64(file_path, &file_stat) == -1) {
            #else
                struct stat file_stat;
                if (stat(file_path, &file_stat) == -1) {
            #endif
                perror("Server: Error getting file stats for download");
                snprintf(response_header, sizeof(response_header), "FILE_DOWNLOAD_ERROR: File '%s' not found or accessible on server.", requested_filename);
                send(sock, response_header, strlen(response_header), 0);
                continue;
            }
            file_size = file_stat.st_size;

            fp = fopen(file_path, "rb");
            if (fp == NULL) {
                perror("Server: Failed to open file for sending");
                snprintf(response_header, sizeof(response_header), "FILE_DOWNLOAD_ERROR: Server failed to open file '%s' for sending.", requested_filename);
                send(sock, response_header, strlen(response_header), 0);
                continue;
            }

            // Send file download header: "FILE_DOWNLOAD_START: <filename> <filesize>"
            snprintf(response_header, sizeof(response_header), "FILE_DOWNLOAD_START: %s %ld", requested_filename, file_size);
            if (send_all(sock, response_header, strlen(response_header)) < 0) {
                perror("Server: Failed to send download header");
                fclose(fp);
                continue;
            }
            // Add a small delay to ensure header is processed before data, or implement ACK
            #ifdef _WIN32
                Sleep(10); // Sleep for 10 milliseconds
            #else
                usleep(10000); // Sleep for 10 milliseconds
            #endif

            printf("Server sending file '%s' (size %ld bytes) to %s.\n", requested_filename, file_size, current_client->nickname);

            // Send file data in chunks
            long total_sent = 0;
            while ((bytes_read = fread(file_buffer, 1, BUFFER_SIZE, fp)) > 0) {
                if (send_all(sock, file_buffer, bytes_read) < 0) {
                    perror("Server: Failed to send file data during download");
                    fclose(fp);
                    break;
                }
                total_sent += bytes_read;
            }

            fclose(fp);
            if (total_sent == file_size) {
                printf("Server successfully sent file '%s' to %s.\n", requested_filename, current_client->nickname);
                snprintf(response_header, sizeof(response_header), "FILE_DOWNLOAD_COMPLETE: %s", requested_filename);
                send(sock, response_header, strlen(response_header), 0); // Confirm completion
            } else {
                printf("Server failed to send complete file '%s' to %s.\n", requested_filename, current_client->nickname);
                snprintf(response_header, sizeof(response_header), "FILE_DOWNLOAD_ERROR: Incomplete transfer for '%s'.", requested_filename);
                send(sock, response_header, strlen(response_header), 0);
            }
            memset(client_message, 0, BUFFER_SIZE);
        }
        // --- Handle File List Request Command ---
        else if (strncmp(client_message, "/listfiles", 10) == 0) {
            printf("%s requested file list.\n", current_client->nickname);
            send_file_list(sock);
            memset(client_message, 0, BUFFER_SIZE);
        }
        // --- Handle Client List Request Command ---
        else if (strncmp(client_message, "/listclients", 12) == 0) {
            printf("%s requested client list.\n", current_client->nickname);
            send_client_list(sock);
            memset(client_message, 0, BUFFER_SIZE);
        }
        // --- Handle Regular Chat Message (or game result) ---
        else {
            // Messages from client now include nickname, so just broadcast
            printf("Received from %s: %s\n", current_client->nickname, client_message);
            // Broadcast to all clients *except* the sender. The sender will display their message locally.
            broadcast_message(client_message, sock);
            memset(client_message, 0, BUFFER_SIZE);
        }
    }

    // Client disconnected or an error occurred
    if (read_size == 0) {
        printf("Client %s (socket %d) disconnected\n", current_client->nickname, sock);
        char leave_msg[BUFFER_SIZE];
        snprintf(leave_msg, sizeof(leave_msg), "SERVER: %s has left the chat.", current_client->nickname);
        broadcast_message(leave_msg, sock); // Announce leave to others
    } else if (read_size == -1) {
        perror("recv failed");
    }

    remove_client(sock);
    close(sock);
    free(socket_desc);

    return NULL;
}

// --- Main Server Function ---
int main() {
    int server_socket, new_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    pthread_t thread_id;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }
#endif

    // Initialize client info array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].sock = 0;
        clients[i].authenticated = 0;
        memset(clients[i].nickname, 0, sizeof(clients[i].nickname));
    }

    // Create upload directory if it doesn't exist
#ifdef _WIN32
    if (_mkdir(UPLOAD_DIR) == -1) {
        if (errno != EEXIST) {
            perror("Failed to create upload directory");
            return 1;
        }
    }
#else
    if (mkdir(UPLOAD_DIR, 0777) == -1) {
        if (errno != EEXIST) {
            perror("Failed to create upload directory");
            return 1;
        }
    }
#endif
    printf("File transfer directory '%s' ensured.\n", UPLOAD_DIR);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }
    printf("Server socket created successfully.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket bound to port %d\n", PORT);

    if (listen(server_socket, MAX_PENDING_CONNECTIONS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d...\n", PORT);

    client_len = sizeof(struct sockaddr_in);

    while ((new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len))) {
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        add_client(new_socket);

        int *p_new_socket = (int*) malloc(sizeof(int));
        if (p_new_socket == NULL) {
            perror("malloc failed");
            close(new_socket);
            remove_client(new_socket);
            continue;
        }
        *p_new_socket = new_socket;

        if (pthread_create(&thread_id, NULL, handle_client, (void*) p_new_socket) < 0) {
            perror("Could not create thread");
            close(new_socket);
            remove_client(new_socket);
            free(p_new_socket);
            continue;
        }
        pthread_detach(thread_id);
    }

    close(server_socket);
    printf("Server shut down.\n");

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
