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
    #include <unistd.h>         // POSIX operating system API (close)
    #include <sys/socket.h>     // Socket programming functions (socket, connect, send, recv)
    #include <netinet/in.h>     // Internet domain addresses (sockaddr_in, htons)
    #include <arpa/inet.h>      // Functions for manipulating IP addresses (inet_addr)
    #include <sys/stat.h>       // For stat()
    #include <dirent.h>         // For opendir, readdir, closedir (for /viewdownloads)
#endif

#include <stdio.h>          // Standard I/O functions (printf, perror, fgets, fopen, fclose, fread)
#include <stdlib.h>         // Standard library functions (exit)
#include <string.h>         // String manipulation functions (strlen, memset, strcspn, strncmp)
#include <pthread.h>        // POSIX threads for concurrency
#include <errno.h>          // For errno
#include <stdarg.h>         // For va_list in safe_print
#include <ctype.h>          // For isspace // Added this include

// Define the port number the server is listening on
#define PORT 8080
// Define the maximum number of pending connections in the listen queue
#define MAX_PENDING_CONNECTIONS 5
// Define the buffer size for messages and file chunks
#define BUFFER_SIZE 1024
// Define the directory where downloaded files will be stored
#define DOWNLOAD_DIR "client_downloads/"
// Max nickname length
#define NICKNAME_MAX_LEN 32
// Max password length
#define PASSWORD_MAX_LEN 32

// Global variable for the client socket, so it can be accessed by the receive thread
int client_socket;
// Mutex to protect stdout for synchronized printing
pthread_mutex_t stdout_mutex = PTHREAD_MUTEX_INITIALIZER;
// Flag to indicate if the "Enter message: " prompt is currently active
volatile int is_prompt_active = 0;
// Client's chosen nickname
char client_nickname[NICKNAME_MAX_LEN + 1];
// Client's password
char client_password[PASSWORD_MAX_LEN + 1];
// Authentication status
volatile int is_authenticated = 0;
// Flag to indicate if any file transfer (upload or download) is in progress
volatile int is_file_transfer_active = 0;

// --- Helper Functions ---

// Function to print a message safely, handling the prompt
void safe_print(const char *format, ...) {
    pthread_mutex_lock(&stdout_mutex);
    if (is_prompt_active) {
        // Clear the current line where the prompt might be
        printf("\r%*s\r", 80, ""); // Print 80 spaces and then carriage return to clear
        fflush(stdout);
    }

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);

    if (is_prompt_active) {
        printf("Enter message: ");
        fflush(stdout);
    }
    pthread_mutex_unlock(&stdout_mutex);
}

// Function to safely send a specified number of bytes
ssize_t send_all(int sock, const void *buffer, size_t length) {
    size_t total_sent = 0;
    ssize_t bytes_sent;
    const char *buf_ptr = (const char *)buffer;

    while (total_sent < length) {
        bytes_sent = send(sock, buf_ptr + total_sent, length - total_sent, 0);
        if (bytes_sent <= 0) {
            return bytes_sent;
        }
        total_sent += bytes_sent;
    }
    return total_sent;
}

// Function to safely receive a specified number of bytes
ssize_t recv_all(int sock, void *buffer, size_t length) {
    size_t total_received = 0;
    ssize_t bytes_received;
    char *buf_ptr = (char *)buffer;

    while (total_received < length) {
        bytes_received = recv(sock, buf_ptr + total_received, length - total_received, 0);
        if (bytes_received <= 0) {
            return bytes_received;
        }
        total_received += bytes_received;
    }
    return total_received;
}

// --- Structure to pass arguments to the download thread ---
typedef struct {
    int socket;
    char filename[256];
    long filesize;
} download_args_t;

// --- Structure to pass arguments to the upload thread ---
typedef struct {
    int socket;
    char file_path[256];
} upload_args_t;


// --- Dedicated Thread Function for File Downloads ---
void *download_file_thread(void *arg) {
    download_args_t *args = (download_args_t *)arg;
    int sock = args->socket;
    char *filename = args->filename;
    long expected_file_size = args->filesize;

    FILE *fp = NULL;
    char file_buffer[BUFFER_SIZE];
    long bytes_received_for_file = 0;
    ssize_t current_bytes_received;
    char save_path[256];

    snprintf(save_path, sizeof(save_path), "%s%s", DOWNLOAD_DIR, filename);

    fp = fopen(save_path, "wb");
    if (fp == NULL) {
        safe_print("Client: Error opening file for writing download in download thread: %s\n", strerror(errno));
        safe_print("Failed to save downloaded file '%s'.\n", filename);
        free(args); // Free allocated memory for args
        is_file_transfer_active = 0; // Reset flag on failure
        return NULL; // Exit thread
    }

    safe_print("\nStarting download of '%s' (%ld bytes) to '%s'...\n", filename, expected_file_size, save_path);


    // Receive file data
    while (bytes_received_for_file < expected_file_size) {
        long bytes_to_read = expected_file_size - bytes_received_for_file;
        if (bytes_to_read > BUFFER_SIZE) {
            bytes_to_read = BUFFER_SIZE;
        }

        current_bytes_received = recv_all(sock, file_buffer, bytes_to_read);

        if (current_bytes_received <= 0) {
            safe_print("Client: Error receiving file data during download or server disconnected.\n");
            fclose(fp);
            remove(save_path); // Delete incomplete file
            safe_print("Download of '%s' failed due to network error.\n", filename);
            free(args);
            is_file_transfer_active = 0; // Reset flag on failure
            return NULL;
        }

        if (fwrite(file_buffer, 1, current_bytes_received, fp) != current_bytes_received) {
            safe_print("Client: Error writing downloaded file data to disk: %s\n", strerror(errno));
            fclose(fp);
            remove(save_path); // Delete incomplete file
            safe_print("Download of '%s' failed due to disk write error.\n", filename);
            free(args);
            is_file_transfer_active = 0; // Reset flag on failure
            return NULL;
        }
        bytes_received_for_file += current_bytes_received;

        // Print progress bar
        pthread_mutex_lock(&stdout_mutex);
        if (is_prompt_active) {
            printf("\r%*s\r", 80, ""); // Clear line before printing progress
        }
        int progress_percent = (int)(((double)bytes_received_for_file / expected_file_size) * 100);
        int bar_length = 50;
        int filled_length = (int)(((double)progress_percent / 100) * bar_length);
        printf("Downloading '%s': [", filename);
        for (int i = 0; i < filled_length; i++) {
            printf("#");
        }
        for (int i = 0; i < (bar_length - filled_length); i++) {
            printf("-");
        }
        printf("] %d%% (%ld/%ld bytes)", progress_percent, bytes_received_for_file, expected_file_size);
        fflush(stdout);
        if (is_prompt_active) {
            printf("\n"); // Move to next line for prompt
            printf("Enter message: ");
            fflush(stdout);
        }
        pthread_mutex_unlock(&stdout_mutex);
    }

    fclose(fp);
    safe_print("\nDownload of '%s' completed successfully.\n", filename);
    free(args); // Free allocated memory for args
    is_file_transfer_active = 0; // Signal that download is complete
    return NULL; // Thread exits
}

// --- Dedicated Thread Function for File Uploads ---
void *send_file_thread(void *arg) {
    upload_args_t *args = (upload_args_t *)arg;
    int sock = args->socket;
    char *file_path = args->file_path;

    FILE *fp;
    long file_size;
    char file_buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    char header[BUFFER_SIZE];

    #ifdef _WIN32
        struct _stat64 file_stat; // Use _stat64 for Windows
        if (_stat64(file_path, &file_stat) == -1) {
    #else
        struct stat file_stat; // Use stat for Linux/macOS
        if (stat(file_path, &file_stat) == -1) {
    #endif
        safe_print("Client: Error getting file stats for upload: %s\n", strerror(errno));
        safe_print("Failed to send file: '%s' not found or accessible.\n", file_path);
        free(args);
        is_file_transfer_active = 0; // Reset flag on failure
        return NULL;
    }
    file_size = file_stat.st_size;

    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        safe_print("Client: Error opening file for reading upload: %s\n", strerror(errno));
        safe_print("Failed to send file: Could not open '%s'.\n", file_path);
        free(args);
        is_file_transfer_active = 0; // Reset flag on failure
        return NULL;
    }

    char *filename = strrchr(file_path, '/');
    if (filename == NULL) {
        filename = strrchr(file_path, '\\');
    }
    if (filename != NULL) {
        filename++;
    } else {
        filename = file_path;
    }

    snprintf(header, sizeof(header), "/sendfile %s %ld", filename, file_size);
    if (send_all(sock, header, strlen(header)) < 0) {
        safe_print("Client: Failed to send file header: %s\n", strerror(errno));
        fclose(fp);
        free(args);
        is_file_transfer_active = 0; // Reset flag on failure
        return NULL;
    }
    safe_print("Sending file header: %s\n", header);

    #ifdef _WIN32
        Sleep(10); // Small delay to ensure header is processed
    #else
        usleep(10000); // Small delay (10ms)
    #endif

    long total_sent = 0;
    while ((bytes_read = fread(file_buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (send_all(sock, file_buffer, bytes_read) < 0) {
            safe_print("Client: Failed to send file data during upload: %s\n", strerror(errno));
            fclose(fp);
            break;
        }
        total_sent += bytes_read;

        // Print upload progress bar
        pthread_mutex_lock(&stdout_mutex);
        if (is_prompt_active) {
            printf("\r%*s\r", 80, ""); // Clear line before printing progress
        }
        int progress_percent = (int)(((double)total_sent / file_size) * 100);
        int bar_length = 50;
        int filled_length = (int)(((double)progress_percent / 100) * bar_length);
        printf("\rUploading '%s': [", filename);
        for (int i = 0; i < filled_length; i++) {
            printf("#");
        }
        for (int i = 0; i < (bar_length - filled_length); i++) {
            printf("-");
        }
        printf("] %d%% (%ld/%ld bytes)", progress_percent, total_sent, file_size);
        fflush(stdout);
        if (is_prompt_active) {
            printf("\n"); // Move to next line for prompt
            printf("Enter message: ");
            fflush(stdout);
        }
        pthread_mutex_unlock(&stdout_mutex);
    }

    fclose(fp);
    if (total_sent == file_size) {
        safe_print("\nFile '%s' sent successfully (%ld bytes).\n", filename, file_size);
    } else {
        safe_print("\nFile '%s' transfer incomplete or failed.\n", filename);
    }

    free(args);
    is_file_transfer_active = 0; // Signal that upload is complete
    return NULL;
}


// --- Thread Function to Receive Messages ---
void *receive_messages(void *arg) {
    char server_reply[BUFFER_SIZE];
    int read_size;

    while (1) {
        // If a file transfer (upload or download) is active, this thread should NOT call recv.
        // The dedicated transfer thread is responsible for reading from client_socket.
        if (is_file_transfer_active) {
            #ifdef _WIN32
                Sleep(10); // Small delay to yield CPU, wait for transfer to finish
            #else
                usleep(10000); // Small delay to yield CPU (10ms)
            #endif
            continue; // Skip recv and loop again
        }

        // Only call recv if no file transfer is active
        read_size = recv(client_socket, server_reply, BUFFER_SIZE - 1, 0);

        if (read_size > 0) {
            server_reply[read_size] = '\0';

            // Trim trailing whitespace (including \r and \n) from server_reply
            int len = strlen(server_reply);
            while (len > 0 && (server_reply[len-1] == '\n' || server_reply[len-1] == '\r' || isspace(server_reply[len-1]))) {
                server_reply[--len] = '\0';
            }

            // --- Handle incoming file download start signal ---
            if (strncmp(server_reply, "FILE_DOWNLOAD_START: ", 21) == 0) {
                char *token;
                char temp_reply[BUFFER_SIZE];
                strcpy(temp_reply, server_reply + 21); // Skip "FILE_DOWNLOAD_START: "

                token = strtok(temp_reply, " "); // filename
                char *filename_str = token;
                token = strtok(NULL, " "); // filesize
                char *filesize_str = token;

                if (filename_str && filesize_str) {
                    long filesize = atol(filesize_str);

                    // Allocate arguments for the new download thread
                    download_args_t *download_args = (download_args_t *)malloc(sizeof(download_args_t));
                    if (download_args == NULL) {
                        safe_print("Client: Failed to allocate memory for download thread arguments.\n");
                    } else {
                        download_args->socket = client_socket;
                        strncpy(download_args->filename, filename_str, sizeof(download_args->filename) - 1);
                        download_args->filename[sizeof(download_args->filename) - 1] = '\0';
                        download_args->filesize = filesize;

                        is_file_transfer_active = 1; // Set flag BEFORE spawning thread
                        pthread_t download_tid;
                        if (pthread_create(&download_tid, NULL, download_file_thread, (void*) download_args) < 0) {
                            safe_print("Client: Failed to start file download thread.\n");
                            free(download_args);
                            is_file_transfer_active = 0; // Reset flag on failure
                        } else {
                            pthread_detach(download_tid);
                        }
                    }
                } else {
                    safe_print("Client: Invalid file download start message from server.\n");
                }
                // Explicitly clear the buffer to prevent binary data from being printed
                memset(server_reply, 0, BUFFER_SIZE);
                continue; // This ensures the loop restarts and `is_file_transfer_active` prevents further `recv`
            }
            // --- Handle incoming file download complete signal (from server) ---
            else if (strncmp(server_reply, "FILE_DOWNLOAD_COMPLETE: ", 24) == 0) {
                // The download_file_thread already prints completion. This is just server's ACK.
                safe_print("\nServer confirmed download of '%s' complete.\n", server_reply + 24);
            }
            // --- Handle incoming file download error signal ---
            else if (strncmp(server_reply, "FILE_DOWNLOAD_ERROR: ", 21) == 0) {
                safe_print("\nDownload error: %s\n", server_reply + 21);
            }
            // --- Handle client list update ---
            else if (strncmp(server_reply, "CLIENT_LIST: ", 13) == 0) {
                safe_print("\n--- Connected Clients ---\n%s\n-------------------------\n", server_reply + 13);
            }
            // --- Handle authentication response ---
            else if (strncmp(server_reply, "AUTH_SUCCESS", 12) == 0) {
                is_authenticated = 1;
                safe_print("\nAuthentication successful! You can now chat and use commands.\n");
            }
            else if (strncmp(server_reply, "AUTH_FAILURE", 12) == 0) {
                is_authenticated = 0;
                safe_print("\nAuthentication failed. Please check your password. Exiting.\n");
                exit(EXIT_FAILURE); // Exit on auth failure
            }
            // --- Handle other messages (chat, upload notifications, file list) ---
            else {
                // Construct the expected prefix for our own messages
                char my_message_prefix[NICKNAME_MAX_LEN + 3]; // e.g., "Nischal: "
                int prefix_len = snprintf(my_message_prefix, sizeof(my_message_prefix), "%s: ", client_nickname);

                // Check if it's a server system message (always print)
                // Also check if the received message starts with our own nickname.
                // If it's a system message, print it. If it's our own chat message, do NOT print it.
                // Otherwise, it's a message from another client, print it.
                if (strncmp(server_reply, "SERVER:", 7) == 0 ||
                    strncmp(server_reply, "FILE_UPLOADED:", 14) == 0)
                {
                    safe_print("\n%s\n", server_reply);
                }
                else if (len >= prefix_len && strncmp(server_reply, my_message_prefix, prefix_len) == 0) {
                    // This is our own chat message echoed back by the server.
                    // We already printed it as "Me: message" locally.
                    // Do nothing here to avoid duplicate.
                }
                else {
                    // It's a message from another client, print it.
                    safe_print("\n%s\n", server_reply);
                }
            }
        } else if (read_size == 0) {
            safe_print("Server disconnected.\n");
            break;
        } else if (read_size == -1) {
            #ifdef _WIN32
                int wsa_error = WSAGetLastError();
                if (wsa_error == WSAECONNRESET) {
                    safe_print("Server reset the connection.\n");
                } else if (wsa_error == WSAEINTR) {
                    continue; // Interrupted system call, can happen with pthread_cancel
                } else {
                    safe_print("recv failed with error %d\n", wsa_error);
                }
            #else
                safe_print("recv failed: %s\n", strerror(errno));
            #endif
            break;
        }
    }

    exit(EXIT_SUCCESS); // Exit the client application if the receive thread terminates
}

// Function to list files in the client_downloads directory
void list_downloaded_files() {
    char path[256];
    snprintf(path, sizeof(path), "%s", DOWNLOAD_DIR);
    safe_print("\n--- Downloaded Files (%s) ---\n", path);

#ifdef _WIN32
    WIN32_FIND_DATAA findFileData;
    char search_path[260]; // Enough for path + "*" + null terminator
    snprintf(search_path, sizeof(search_path), "%s*", path); // Correctly form search path
    HANDLE hFind = FindFirstFileA(search_path, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        safe_print("No files found or directory error: %s\n", strerror(errno));
        return;
    }

    int file_count = 0;
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            safe_print("- %s\n", findFileData.cFileName);
            file_count++;
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);
    FindClose(hFind);
    if (file_count == 0) {
        safe_print("(No files in this directory)\n");
    }
#else // Linux/macOS
    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if (d) {
        int file_count = 0;
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) { // Check if it's a regular file
                safe_print("- %s\n", dir->d_name);
                file_count++;
            }
        }
        closedir(d);
        if (file_count == 0) {
            safe_print("(No files in this directory)\n");
        }
    } else {
        safe_print("Error opening download directory: %s\n", strerror(errno));
    }
#endif
    safe_print("-----------------------------\n");
}


// --- Main Client Function ---
int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;
    char message[BUFFER_SIZE];
    pthread_t recv_thread;
    const char *server_ip;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }
#endif

    // Check for command-line argument for server IP
    if (argc < 2) {
        printf("Usage: %s <server_ip_address>\n", argv[0]);
        printf("Example: %s 127.0.0.1\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    server_ip = argv[1];

    // Prompt for nickname
    printf("Enter your nickname (max %d chars): ", NICKNAME_MAX_LEN);
    fflush(stdout);
    if (fgets(client_nickname, NICKNAME_MAX_LEN, stdin) == NULL) {
        perror("fgets failed for nickname");
        exit(EXIT_FAILURE);
    }
    client_nickname[strcspn(client_nickname, "\n")] = 0; // Remove newline
    if (strlen(client_nickname) == 0) {
        strcpy(client_nickname, "Guest"); // Default nickname if empty
    }
    printf("Welcome, %s!\n", client_nickname);

    // Prompt for password
    printf("Enter password (max %d chars): ", PASSWORD_MAX_LEN);
    fflush(stdout);
    if (fgets(client_password, PASSWORD_MAX_LEN, stdin) == NULL) {
        perror("fgets failed for password");
        exit(EXIT_FAILURE);
    }
    client_password[strcspn(client_password, "\n")] = 0; // Remove newline


    // Create download directory if it doesn't exist
#ifdef _WIN32
    if (_mkdir(DOWNLOAD_DIR) == -1) {
        if (errno != EEXIST) {
            perror("Failed to create download directory");
            return 1;
        }
    }
#else
    if (mkdir(DOWNLOAD_DIR, 0777) == -1) {
        if (errno != EEXIST) {
            perror("Failed to create download directory");
            return 1;
        }
    }
#endif
    printf("Download directory '%s' ensured.\n", DOWNLOAD_DIR);


    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }
    printf("Client socket created.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    // Use inet_pton for cross-platform IP conversion
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/ Address not supported\n");
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed. Check server IP and port, and ensure server is running.");
        exit(EXIT_FAILURE);
    }
    printf("Connected to server %s:%d\n", server_ip, PORT);

    // Send nickname and password to server immediately after connecting
    char auth_msg[BUFFER_SIZE];
    snprintf(auth_msg, sizeof(auth_msg), "/auth %s %s", client_nickname, client_password);
    if (send(client_socket, auth_msg, strlen(auth_msg), 0) < 0) {
        perror("Failed to send authentication message to server");
    }
    printf("Attempting to authenticate...\n");


    // Create the receive thread
    if (pthread_create(&recv_thread, NULL, receive_messages, NULL) < 0) {
        perror("Could not create receive thread");
        exit(EXIT_FAILURE);
    }
    pthread_detach(recv_thread); // Detach the receive thread

    // Main loop for sending messages (user input)
    while (1) {
        // Wait until authenticated before showing main prompt and allowing commands
        while (!is_authenticated) {
            #ifdef _WIN32
                Sleep(100); // Wait 100ms
            #else
                usleep(100000); // Wait 100ms
            #endif
            // Check if receive thread exited due to auth failure
            if (!is_authenticated && client_socket == -1) { // client_socket set to -1 on exit
                return 1;
            }
        }

        // Read input from stdin (blocking call)
        // is_prompt_active is set/unset around fgets to ensure safe_print knows when to clear line
        // No mutex lock/unlock here, safe_print handles it internally
        is_prompt_active = 1; // Set prompt flag before printing prompt
        printf("Enter message: ");
        fflush(stdout);
        
        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            perror("fgets failed");
            break;
        }

        is_prompt_active = 0; // Temporarily unset prompt flag as we're processing input

        message[strcspn(message, "\n")] = 0; // Remove newline

        if (strcmp(message, "exit") == 0) {
            printf("Exiting chat.\n");
            fflush(stdout);
            break;
        }
        // --- Handle /help command ---
        else if (strcmp(message, "/help") == 0) {
            printf("\n--- Available Commands ---\n");
            printf("  Type your message to chat.\n");
            printf("  /sendfile <path_to_local_file> - Upload a file to the server.\n");
            printf("  /listfiles                       - List files available on the server.\n");
            printf("  /getfile <filename>              - Download a file from the server.\n");
            printf("  /viewdownloads                   - View files in your local downloads folder.\n");
            printf("  /listclients                     - View currently connected clients.\n");
            printf("  exit                             - Quit the client.\n");
            printf("--------------------------\n");
        }
        // --- Handle File Upload Command ---
        else if (strncmp(message, "/sendfile ", 10) == 0) {
            if (is_file_transfer_active) {
                safe_print("A file transfer is already in progress. Please wait.\n");
                continue;
            }

            char *file_path = message + 10;
            
            // Allocate arguments for the new upload thread
            upload_args_t *upload_args = (upload_args_t *)malloc(sizeof(upload_args_t));
            if (upload_args == NULL) {
                safe_print("Client: Failed to allocate memory for upload thread arguments.\n");
                continue;
            }
            upload_args->socket = client_socket;
            strncpy(upload_args->file_path, file_path, sizeof(upload_args->file_path) - 1);
            upload_args->file_path[sizeof(upload_args->file_path) - 1] = '\0';

            is_file_transfer_active = 1; // Set flag BEFORE spawning thread
            pthread_t upload_tid;
            if (pthread_create(&upload_tid, NULL, send_file_thread, (void*) upload_args) < 0) {
                safe_print("Client: Failed to start file upload thread.\n");
                free(upload_args);
                is_file_transfer_active = 0; // Reset flag on failure
                continue;
            }
            pthread_detach(upload_tid); // Detach the thread
        }
        // --- Handle File List Command ---
        else if (strncmp(message, "/listfiles", 10) == 0) {
            if (send(client_socket, message, strlen(message), 0) < 0) {
                perror("Send /listfiles failed");
            }
        }
        // --- Handle File Download Command ---
        else if (strncmp(message, "/getfile ", 9) == 0) {
            if (is_file_transfer_active) {
                safe_print("A file transfer is already in progress. Please wait.\n");
                continue;
            }
            if (send(client_socket, message, strlen(message), 0) < 0) {
                perror("Send /getfile failed");
            }
        }
        // --- Handle View Downloads Command ---
        else if (strncmp(message, "/viewdownloads", 14) == 0) {
            // This function itself does not block network I/O, but prints to console
            list_downloaded_files();
        }
        // --- Handle List Clients Command ---
        else if (strncmp(message, "/listclients", 12) == 0) {
            if (send(client_socket, message, strlen(message), 0) < 0) {
                perror("Send /listclients failed");
            }
        }
        else {
            // Message to send to server (Nickname: message)
            char server_message[BUFFER_SIZE + NICKNAME_MAX_LEN + 5];
            snprintf(server_message, sizeof(server_message), "%s: %s", client_nickname, message);

            if (send(client_socket, server_message, strlen(server_message), 0) < 0) {
                perror("Send chat message failed");
            }

            // Message to display locally (Me: message)
            char local_display_message[BUFFER_SIZE + 5]; // "Me: " + message
            snprintf(local_display_message, sizeof(local_display_message), "Me: %s", message);
            safe_print("%s\n", local_display_message);
        }
    }

    close(client_socket);
    printf("Client socket closed.\n");

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
