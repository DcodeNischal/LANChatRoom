# Cross-Platform C/C++ LAN Chat Room with File Transfer

## Authors

**_Ajay Shankar Singh, 201702, BE Software (Day)_**

**_Nischal Dhakal, 201720, BE Software (Day)_**

## Brief Project Description

_This project implements a **cross-platform LAN Chat Room** using C/C++ and native socket APIs (Unix Sockets for Linux/macOS, Winsock for Windows). It features a client-server architecture for real-time text chat and provides enhanced file transfer capabilities, allowing clients to upload files to the server, list available files on the server, and download files from the server. The server handles multiple concurrent connections using POSIX threads._

## Features

- **Cross-Platform Compatibility:** Supports both Unix-like operating systems (Linux, macOS) and Windows.
- **Client-Server Architecture:** A central server manages all client connections and message relay.
- **Multi-Client Support:** The server can handle multiple simultaneous client connections, allowing several users to chat concurrently.
- **Real-time Messaging:** Clients can send text messages that are broadcast to all other connected clients (excluding the sender).
- **Enhanced File Transfer:**
  - **File Upload:** Clients can upload files to the server. Files are stored in a designated `server_files/` directory on the server.
  - **File Listing:** Clients can request and receive a list of all files currently available on the server.
  - **File Download:** Clients can request and download specific files from the server's `server_files/` directory to their local `client_downloads/` directory.
- **Concurrency:** The server utilizes separate POSIX threads (`pthread`) for each connected client, ensuring that incoming messages and file data from one client do not block communication with others.
- **Robust Data Transfer:** Includes `send_all` and `recv_all` helper functions to ensure all bytes of a message or file are sent/received reliably over TCP.
- **Basic Connection Management:** The server tracks connected clients, adds new ones, and removes clients upon disconnection or error.
- **Command-line Interface:** Both the server and client applications operate via the command line, providing a straightforward interface for interaction.

## Dependencies

- **A C/C++ compiler (e.g., GCC, MinGW for Windows, MSVC with appropriate setup).**
- **For Linux/macOS:** Standard C libraries, Unix Sockets (`sys/socket.h`), and POSIX threads (`pthread`).
- **For Windows:** Winsock2 library `winsock2.h`,` ws2tcpip.h`), Windows API for directory creation (`windows.h`, `direct.h`), and POSIX threads (`pthread` - typically available with MinGW-w64 or Cygwin compilers).

## How to Compile

1. **Save the code:**
   - **Save the server code `server.c`.**
   - **Save the client code `client.c`.**
2. **Open a terminal/command prompt** in the directory where you saved the files.
3. **Compile the server:**

   - **Linux/macOS (using GCC):**

     ```
     gcc server.c -o server -pthread
     ```

   - **Windows (using MinGW-w64/GCC):**

     ```
     gcc server.c -o server.exe -lws2_32 -pthread
     ```

     - `-lws2_32`: Links the Winsock library.
     - `-pthread`: Links the POSIX threads library (if using MinGW/Cygwin).

4. **Compile the client:**
   - **Linux/macOS (using GCC):**
     ```
     gcc client.c -o client -pthread
     ```
   - **Windows (using MinGW-w64/GCC):**
     ```
     gcc client.c -o client.exe -lws2_32 -pthread
     ```

## How to Run

1. **Start the Server:**
   Open a terminal/command prompt and run the compiled server executable:

   ```
   # Linux/macOS
   ./chat_server

   # Windows
   .\chat_server.exe
   ```

   **The server will start listening on port `8080` and will create a directory named `server_files/` if it doesn't already exist. This directory will store all uploaded files and serve files for download.**

2. **Start Clients:**
   Open one or more **new terminal/command prompt windows** for each client you want to connect. Run the client executable, providing the server's IP address as an argument:

   ```
   # Linux/macOS
   ./chat_client 127.0.0.1

   # Windows
   .\chat_client.exe 127.0.0.1
   ```

   - _Replace `127.0.0.1` with the actual IP address of the machine running the `chat_server` if it's on a different computer on your network._
   - **You can run multiple clients from the same or different machines.**
   - _Each client will create a `client_downloads/` directory to save downloaded files._

### Client Commands:

- **Send a chat message:**
  Simply type your message and press `Enter`. The message will be sent to the server and broadcast to all other connected clients.
- **Send a file (Upload):**
  To upload a file to the server, use the following command format:

  ```
  /sendfile <path_to_local_file>
  ```

  **Examples:**

  - If `my_document.txt` is in the same directory as `chat_client`:

    ```
    /sendfile my_document.txt
    ```

  - **If the file is in a specific path:**

    ```
    /sendfile /home/user/documents/report.pdf
    ```

    (On Windows, use backslashes: `/sendfile C:\Users\YourUser\Pictures\image.jpg`)

- **List files on server:**
  To see the names of files available for download on the server:

  ```
  /listfiles
  ```

- **Download a file:**
  To download a specific file from the server, use the following command format:

  ```
  /getfile <filename_on_server>
  ```

  **Example:**

  - If `/listfiles` showed `report.pdf `is available:
    ```
    /getfile report.pdf
    ```

  The downloaded file will be saved in the `client_downloads/` directory.

- **Exit the client:**
  Type `exit` and press `Enter`.

## Screenshots

**Here are some screenshots illustrating the chat application in action:**

### Chat Interface

**A view of the chat client console, showing messages being exchanged.**

![C](readmeimage\message.png)

### Authentication

**Screenshot of the client during the authentication process.**

![A](readmeimage\authentication.png)

### File Upload in Action

**A screenshot demonstrating the file upload process and progress.**

![U](readmeimage\upload.png)

### File Download in Action

**A screenshot demonstrating the file download process and progress.**

![D](readmeimage\download.png)

### List Files on Server

**A view of the client console showing the list of files available on the server.**

![L](readmeimage\listfiles.png)

### List Connected Clients

**A view of the client console showing the list of currently connected clients.**

![C](readmeimage\clientlist.png)

### Help Command Output

**A screenshot showing the output of the **`/help`** command.**

![H](readmeimage\help.png)

## Notes and Limitations

- **Compiler Choice:** While `pthread` is used for concurrency, it's generally compatible with MinGW-w64/GCC on Windows, providing a more consistent cross-platform C/C++ experience than using native Windows threading APIs directly.
- **Error Handling:** Basic error handling is implemented. For a production-grade application, more robust error checking, logging, and recovery mechanisms would be necessary.
- **Protocol Simplicity:** The file transfer protocol is still basic. It relies on simple text-based headers (`/sendfile`, `FILE_DOWNLOAD_START`, etc.) followed by raw file data. There's no built-in integrity checking (like checksums) or advanced flow control.
- **Security:** This application has no built-in encryption or authentication. Messages and files are sent in plain text. It is suitable for local network (LAN) use for educational purposes only.
- **File Overwriting:** If a client uploads a file with the same name as one already on the server, the server will overwrite the existing file. Similarly, downloading a file with an existing name will overwrite the local file in `client_downloads/`.
