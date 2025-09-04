<?php
$isAuthenticated = isset($_COOKIE['AUTH_TOKEN']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebSocket Test</title>
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

        function connect() {
            socket = new WebSocket("ws://localhost:8080/ws");

            socket.onopen = function(event) {
                console.log('WebSocket connection opened.');
                statusDiv.textContent = 'Connected';
                statusDiv.style.color = 'green';
            };

            socket.onmessage = function(event) {
                let message = document.createElement("li");
                message.textContent = event.data;
                messagesList.appendChild(message);
            };

            socket.onclose = function(event) {
                console.log('WebSocket connection closed.', event.reason);
                statusDiv.textContent = `Disconnected. (Code: ${event.code})`;
                statusDiv.style.color = 'red';
            };

            socket.onerror = function(error) {
                console.error('WebSocket Error:', error);
            };
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
            
            let message = document.createElement("li");
            message.style.color = 'blue';
            message.textContent = `Subscription request sent for channel "${channel}".`;
            messagesList.appendChild(message);
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = userIdInput.value;
            if (!userId) return;

            try {
                const response = await fetch('/login.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
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