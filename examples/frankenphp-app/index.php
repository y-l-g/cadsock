<?php
$isAuthenticated = isset($_COOKIE['AUTH_TOKEN']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebSocket Test</title>
    <style>
        .msg-system { color: blue; font-style: italic; }
        .msg-error { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>WebSocket Channels</h1>

    <div>
        <strong>Authentication Status:</strong>
        <span id="auth-status" style="color: <?php echo $isAuthenticated ? 'green' : 'red'; ?>;">
            <?php echo $isAuthenticated ? 'Authenticated' : 'Not authenticated'; ?>
        </span>
    </div>

    <form id="login-form" style="margin-top: 10px;">
        <label for="userId">User ID:</label>
        <input type="text" id="userId" value="user-123">
        <button type="submit">Login</button>
        <button type="button" id="logout">Logout</button>
    </form>

    <hr>
    <div id="websocket-ui" style="display: <?php echo $isAuthenticated ? 'block' : 'none'; ?>;">
        <div id="connection-status" style="color: red;">Disconnected</div>
        <hr>
        <div>
            <label for="channel">Channel:</label>
            <input type="text" id="channel" value="news">
            <button id="subscribe">Subscribe to Channel</button>
        </div>
        <hr>
        <h2>Messages received:</h2>
        <ul id="messages"></ul>
    </div>

    <script>
        const isAuthenticated = <?php echo json_encode($isAuthenticated); ?>;

        const authStatus = document.getElementById('auth-status');
        const loginForm = document.getElementById('login-form');
        const userIdInput = document.getElementById('userId');
        const logoutBtn = document.getElementById('logout');
        const websocketUi = document.getElementById('websocket-ui');

        const channelInput = document.getElementById('channel');
        const subscribeBtn = document.getElementById('subscribe');
        const messagesList = document.getElementById('messages');
        const statusDiv = document.getElementById('connection-status');
        
        let socket;
        let reconnectInterval;
        let reconnectAttempts = 0;

        function connect() {
            // Prevent multiple parallel connection attempts
            if (socket && socket.readyState === WebSocket.OPEN) {
                console.log('WebSocket is already connected.');
                return;
            }

            socket = new WebSocket("ws://localhost:8080/ws");

            socket.onopen = function(event) {
                console.log('WebSocket connection opened.');
                statusDiv.textContent = 'Connected';
                statusDiv.style.color = 'green';
                // Reset reconnect attempts on successful connection
                reconnectAttempts = 0;
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
            };

            socket.onmessage = function(event) {
                const messageData = JSON.parse(event.data);
                let li = document.createElement("li");

                switch (messageData.type) {
                    case 'message':
                        // The payload can be any JSON value, we stringify it for display.
                        li.textContent = `(Channel: ${messageData.channel}) Payload: ${JSON.stringify(JSON.parse(messageData.payload))}`;
                        break;
                    case 'subscribed':
                        li.textContent = `Successfully subscribed to channel "${messageData.channel}".`;
                        li.className = 'msg-system';
                        break;
                    case 'unsubscribed':
                         li.textContent = `Successfully unsubscribed from channel "${messageData.channel}".`;
                        li.className = 'msg-system';
                        break;
                     case 'error':
                        li.textContent = `Server Error: ${messageData.error}`;
                        li.className = 'msg-error';
                        break;
                    default:
                        li.textContent = `Unknown message type: ${event.data}`;
                        break;
                }
                messagesList.appendChild(li);
            };

            socket.onclose = function(event) {
                console.log('WebSocket connection closed.', event.reason);
                statusDiv.textContent = `Disconnected. (Code: ${event.code})`;
                statusDiv.style.color = 'red';
                // Attempt to reconnect if the closure was unexpected
                if (event.code !== 1000) { // 1000 is normal closure
                    scheduleReconnect();
                }
            };

            socket.onerror = function(error) {
                console.error('WebSocket Error:', error);
                // An error will likely be followed by a close event, which will trigger reconnection.
            };
        }

        function scheduleReconnect() {
            if (reconnectInterval) return; // Reconnect already scheduled

            reconnectAttempts++;
            // Exponential backoff: 2s, 4s, 8s, 16s, max 30s
            const delay = Math.min(30000, Math.pow(2, reconnectAttempts) * 1000);

            statusDiv.textContent += ` Reconnecting in ${delay / 1000}s...`;
            console.log(`Scheduling reconnect attempt ${reconnectAttempts} in ${delay}ms`);

            reconnectInterval = setTimeout(() => {
                reconnectInterval = null; // Clear the timer ID before attempting to connect
                connect();
            }, delay);
        }

        function subscribeToChannel() {
            const channel = channelInput.value;
            if (!channel) {
                alert('Please enter a channel name.');
                return;
            }

            if (!socket || socket.readyState !== WebSocket.OPEN) {
                alert('Not connected to the WebSocket server.');
                return;
            }

            const subscribeMsg = {
                action: "subscribe",
                channel: channel
            };
            socket.send(JSON.stringify(subscribeMsg));
            console.log(`Sent subscription request for channel: ${channel}`);
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = userIdInput.value;
            if (!userId) return;

            try {
                const response = await fetch('/login.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: userId })
                });

                if (response.ok) {
                    window.location.reload();
                } else {
                    alert('Login failed.');
                }
            } catch (error) {
                console.error('Login request failed:', error);
                alert('Login request failed.');
            }
        });

        logoutBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/logout.php', { method: 'POST' });
                if (response.ok) {
                    window.location.reload();
                } else {
                    alert('Logout failed.');
                }
            } catch (error) {
                console.error('Logout request failed:', error);
                alert('Logout request failed.');
            }
        });

        subscribeBtn.addEventListener('click', subscribeToChannel);
        
        if (isAuthenticated) {
            connect();
        }
    </script>
</body>
</html>